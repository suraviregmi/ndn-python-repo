# -----------------------------------------------------------------------------
# Direct ingest protocol.
#
# One Interest, one Data: the producer sends a single ingest Interest naming
# the Data to be stored; the repo fetches and stores that Data, then replies
# to the same Interest with an empty Data packet as acknowledgement, or with
# an application-level NACK if the command failed. Both replies are signed
# by the repo.
#
# The ingest Interest is a signed Interest carrying SignatureTime and
# SignatureNonce. Its params-sha256 name component covers the parameters and
# the signature, so every command (including a resend) has a distinct name
# and each reply answers exactly one Interest name.
#
# @Author regmisuravi@gmail.com
# @Date   2026-06-30
# -----------------------------------------------------------------------------

import asyncio as aio
import base64
import logging
import os
from pathlib import Path

from ndn.app import NDNApp, ReplyFunc, Validator, ValidResult
from ndn.app_support.light_versec import Checker, LvsModel, TypeNumber, compile_lvs, lvs_validator
from ndn.encoding import Name, NonStrictName, ContentType, tlv_parse
from ndn.security import Keychain
from ndn.security.validator.cascade_validator import MemoryKeyStorage
from .read_handle import ReadHandle
from .utils import fetch_object
from ..command import ObjParam, RepoStatCode
from ..storage import Storage
from typing import Optional


def create_ingest_validator(app: NDNApp, security_config: Optional[dict]) -> Optional[Validator]:
    """
    Create the validator for ingest command Interests from the ``ingest_security`` config section.

    The command Interest is checked against an LVS trust schema, and the signing certificate
    chain is fetched from the network and validated up to the configured trust anchor.

    :param app: NDNApp. Used to fetch certificates in the signing chain.
    :param security_config: the ``ingest_security`` config section, or None.
    :return: the validator, or None if ``ingest_security`` is not configured.
    """
    if not security_config:
        return None

    anchor_path = security_config.get('trust_anchor')
    schema_path = security_config.get('trust_schema')
    if not anchor_path or not schema_path:
        raise ValueError('ingest_security requires both trust_anchor and trust_schema')

    resolved_anchor = Path(os.path.expanduser(os.path.expandvars(anchor_path)))
    anchor_file = resolved_anchor.read_bytes()
    if anchor_file.startswith(b'\x06'):
        trust_anchor = anchor_file
    else:
        trust_anchor = base64.b64decode(b''.join(anchor_file.split()), validate=True)
    resolved_schema = Path(os.path.expanduser(os.path.expandvars(schema_path)))
    schema_file = resolved_schema.read_bytes()
    if schema_file.startswith(bytes([TypeNumber.VERSION])):
        # LVS binary format, compiled from the trust schema elsewhere
        lvs_model = LvsModel.parse(schema_file)
    else:
        lvs_model = compile_lvs(schema_file.decode())

    return lvs_validator(Checker(lvs_model, {}), app, trust_anchor, MemoryKeyStorage())


class DirectIngestHandle:
    """
    Repo-side handler for the direct ingest protocol.
    Listens on <repo_name>/ingest, and processes each command as a single Interest/Data

    1. Producer sends a signed Interest to <repo_name>/ingest/params-sha256=<digest>,
       with AppParam = ObjParam { name, forwarding_hint, ... }.
    2. Repo fetches and stores the requested Data, as in insert.
    3. Repo replies to the original ingest Interest with an empty signed Data packet,
       or with an application-level NACK (ContentType=NACK) if the command failed.
    """

    DEFAULT_INTEREST_LIFETIME_MS = 4000  # NDN default when InterestLifetime is absent
    REPLY_MARGIN_MS = 500  # reply this long before the ingest Interest expires

    def __init__(self, app: NDNApp, storage: Storage, config: dict, read_handle: ReadHandle,
                 interest_validator: Optional[Validator] = None, keychain: Optional[Keychain] = None):
        self.app     = app
        self.storage = storage
        self.config  = config
        self.prefix  = None
        self._registered_prefixes = set()
        self.m_read_handle = read_handle
        self.interest_validator = interest_validator
        # Replies are signed with the repo's default key, so the producer can validate them
        self.signer = None
        if interest_validator is not None:
            if keychain is None:
                keychain = NDNApp.default_keychain()
            self.signer = keychain.get_signer({})

    async def listen(self, prefix: NonStrictName):
        """
        Register Interest filter on <prefix>/ingest.
        Called by WriteCommandHandle.listen().

        :param prefix: NonStrictName. The repo's name prefix.
        """
        if self.interest_validator is None:
            logging.warning('Direct ingest is disabled: ingest_security is not configured')
            return

        self.prefix   = Name.normalize(prefix)
        ingest_prefix = self.prefix + Name.from_str('ingest')
        self.app.attach_handler(ingest_prefix, self._on_insert_interest, self._validate_command)
        await self.app.register(ingest_prefix)
        logging.info(f'DirectIngestHandle listening on {Name.to_str(ingest_prefix)}')

    async def _validate_command(self, name, sig_ptrs, context) -> ValidResult:
        """
        Validate ingest command Interests with ``interest_validator``.
        Unsigned commands bypass it, so that ``_on_insert_interest`` answers them with a NACK
        instead of letting the producer time out.
        """
        if sig_ptrs.signature_info is None:
            return ValidResult.ALLOW_BYPASS
        return await self.interest_validator(name, sig_ptrs, context)

    # Ingest Interest entry point.

    def _on_insert_interest(self, int_name, app_param, reply: ReplyFunc, context):
        """
        Check the command, and start fetching only if it is well-formed.
        Rejected commands are answered here, without creating a task.
        """
        sig_ptrs = context['sig_ptrs']
        if sig_ptrs is None or sig_ptrs.signature_info is None:
            logging.warning(f'ingest.reject.unsigned {Name.to_str(int_name)}')
            self._reply_nack(int_name, reply)
            return
        if sig_ptrs.signature_info.signature_time is None:
            logging.warning(f'ingest.reject.missing_sig_time {Name.to_str(int_name)}')
            self._reply_nack(int_name, reply)
            return
        if sig_ptrs.signature_info.signature_nonce is None:
            logging.warning(f'ingest.reject.missing_sig_nonce {Name.to_str(int_name)}')
            self._reply_nack(int_name, reply)
            return

        try:
            param = tlv_parse(ObjParam, app_param)
        except Exception as e:
            logging.warning(f'ingest.parse.fail: {e}')
            self._reply_nack(int_name, reply)
            return

        logging.info(f'ingest.received {Name.to_str(int_name)}')
        aio.create_task(self._process_insert(int_name, context['int_param'], param, reply))

    async def _process_insert(self, int_name, int_param, param: ObjParam, reply: ReplyFunc):
        """
        Fetch and store the requested Data, then reply to int_name with an empty
        Data packet as acknowledgement, or with an application-level NACK
        (ContentType=NACK) on failure.
        """
        # Fetch, bounded by the ingest Interest's lifetime so that the reply
        # (ack or NACK) still reaches the producer before its PIT entry expires.
        lifetime = (int_param.lifetime if int_param and int_param.lifetime is not None
                    else self.DEFAULT_INTEREST_LIFETIME_MS)
        deadline_s = max(lifetime - self.REPLY_MARGIN_MS, 0) / 1000.0
        try:
            status_code, insert_num = await aio.wait_for(
                fetch_object(self.app, self.storage, param), timeout=deadline_s)
        except aio.TimeoutError:
            logging.error(f'ingest.fetch.deadline {Name.to_str(int_name)} deadline={deadline_s}s')
            self._reply_nack(int_name, reply)
            return

        if status_code == RepoStatCode.MALFORMED:
            logging.warning(f'ingest.malformed {Name.to_str(int_name)}')
            self._reply_nack(int_name, reply)
            return
        data_name = Name.to_str(param.name)
        if status_code != RepoStatCode.COMPLETED:
            logging.error(f'ingest.fetch.fail {data_name} inserted={insert_num}')
            self._reply_nack(int_name, reply)
            return

        logging.info(f'ingest.data.saved {data_name} count={insert_num}')

        register_prefix = param.register_prefix.name if param.register_prefix else None
        if register_prefix:
            prefix_str = Name.to_str(register_prefix)
            if prefix_str not in self._registered_prefixes:
                self._registered_prefixes.add(prefix_str)
                self.m_read_handle.listen(register_prefix)
                logging.info(f'ingest.prefix.registered {prefix_str}')

        # Ack
        reply(self.app.make_data(int_name, None, self.signer))
        logging.info(f'ingest.ack.sent data={data_name}')

    def _reply_nack(self, int_name, reply: ReplyFunc):
        """
        Reply to the ingest Interest with an application-level NACK, so the
        producer learns about the failure without waiting for its Interest to time out.
        """
        reply(self.app.make_data(int_name, None, self.signer, content_type=ContentType.NACK))
        logging.info(f'ingest.nack.sent {Name.to_str(int_name)}')
