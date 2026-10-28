import asyncio as aio
import base64
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest
from Cryptodome.PublicKey import ECC
from ndn.app_support.light_versec import compile_lvs
from ndn.app_support.security_v2 import self_sign, derive_cert
from ndn.encoding import Name, Component, ContentType, InterestParam, make_interest, parse_interest, parse_data
from ndn.security import Sha256WithEcdsaSigner, DigestSha256Signer
from ndn.types import ValidationFailure, InterestTimeout, ValidResult
from ndn_python_repo.clients.ingest import _CommandSigner
from ndn_python_repo.command import ObjParam
from ndn_python_repo.handle.ingest_handle import DirectIngestHandle, create_ingest_validator


SCHEMA = '''
#KEY: "KEY"/_/_/_
#root: "test-root"/#KEY
#producer_a: "producer-a"/#KEY <= #root
#producer_b: "producer-b"/#KEY <= #root
#ingest: "repo"/"ingest"/_ <= #producer_a | #producer_b
'''


def make_key(key_name):
    key = ECC.generate(curve='P-256')
    return (Name.from_str(key_name) + [Component.from_bytes(b'k')],
            key.public_key().export_key(format='DER'), key.export_key(format='DER'))


@pytest.fixture
def pki(tmp_path):
    root_key, root_pub, root_priv = make_key('/test-root/KEY')
    root_cert_name, root_cert = self_sign(root_key, root_pub, Sha256WithEcdsaSigner(root_key, root_priv))
    producer_signers = []
    certs = {}
    for producer_name in ('/producer-a/KEY', '/producer-b/KEY', '/producer-c/KEY'):
        prod_key, prod_pub, prod_priv = make_key(producer_name)
        prod_cert_name, prod_cert = derive_cert(
            prod_key, 'root', prod_pub, Sha256WithEcdsaSigner(root_cert_name, root_priv),
            datetime.now(timezone.utc), 3600)
        producer_signers.append(Sha256WithEcdsaSigner(prod_cert_name, prod_priv))
        certs[Name.to_bytes(prod_cert_name)] = bytes(prod_cert)

    anchor_path = tmp_path / 'anchor.ndncert'
    anchor_path.write_bytes(base64.b64encode(bytes(root_cert)))
    schema_path = tmp_path / 'ingest.lvs'
    schema_path.write_text(SCHEMA)

    async def express(name, validator, **_kwargs):
        # Serve certificates like the network would, validating each with the given validator
        wire = certs.get(Name.to_bytes(name))
        if wire is None:
            raise InterestTimeout()
        data_name, meta_info, content, sig_ptrs = parse_data(wire)
        context = {'meta_info': meta_info, 'sig_ptrs': sig_ptrs, 'raw_packet': wire}
        result = await validator(data_name, sig_ptrs, context)
        if result not in (ValidResult.PASS, ValidResult.ALLOW_BYPASS):
            raise ValidationFailure(data_name, meta_info, content, sig_ptrs, result)
        return data_name, content, context

    app = Mock()
    app.express = AsyncMock(side_effect=express)
    config = {'trust_anchor': str(anchor_path), 'trust_schema': str(schema_path)}
    return app, config, *producer_signers


def signed_command(name, signer):
    wire = make_interest(Name.from_str(name), InterestParam(lifetime=10000), b'\x07\x00', signer=signer)
    int_name, _, _, sig_ptrs = parse_interest(wire)
    return int_name, sig_ptrs


def validate(validator, int_name, sig_ptrs):
    return aio.run(validator(int_name, sig_ptrs, {})) == ValidResult.PASS


def command_context(sig_ptrs, int_param=None):
    return {'int_param': int_param or InterestParam(), 'sig_ptrs': sig_ptrs}


def test_ingest_is_disabled_without_security_config():
    assert create_ingest_validator(Mock(), None) is None


def test_ingest_security_requires_anchor_and_schema(pki):
    _, config, _, _, _ = pki
    with pytest.raises(ValueError, match='trust_anchor and trust_schema'):
        create_ingest_validator(Mock(), {'trust_schema': config['trust_schema']})


def test_ingest_security_expands_user_home_in_paths(pki, tmp_path, monkeypatch):
    app, config, _, _, _ = pki
    home_dir = tmp_path / 'home'
    home_dir.mkdir()
    anchor_path = home_dir / 'anchor.ndncert'
    schema_path = home_dir / 'ingest.lvs'
    anchor_path.write_bytes(Path(config['trust_anchor']).read_bytes())
    schema_path.write_text(Path(config['trust_schema']).read_text())

    monkeypatch.setenv('HOME', str(home_dir))
    validator = create_ingest_validator(app, {
        'trust_anchor': '~/anchor.ndncert',
        'trust_schema': '~/ingest.lvs',
    })
    assert validator is not None


def test_ingest_security_rejects_anchor_not_matching_schema(pki, tmp_path):
    app, config, _, _, _ = pki
    schema_path = tmp_path / 'other.lvs'
    schema_path.write_text(SCHEMA.replace('"test-root"', '"other-root"'))
    with pytest.raises(ValueError, match='Trust anchor'):
        create_ingest_validator(app, {**config, 'trust_schema': str(schema_path)})


def test_ingest_validator_fetches_chain_and_accepts_authorized_producer(pki):
    app, config, producer_a_signer, producer_b_signer, _ = pki
    validator = create_ingest_validator(app, config)

    for signer in (producer_a_signer, producer_b_signer):
        int_name, sig_ptrs = signed_command('/repo/ingest', _CommandSigner(signer))
        assert sig_ptrs.signature_info.signature_time is not None
        assert sig_ptrs.signature_info.signature_nonce is not None
        assert validate(validator, int_name, sig_ptrs)
    assert app.express.await_count == 2


def test_ingest_security_accepts_lvs_binary_schema(pki, tmp_path):
    app, config, producer_signer, _, _ = pki
    schema_path = tmp_path / 'ingest.lvsb'
    schema_path.write_bytes(compile_lvs(SCHEMA).encode())
    validator = create_ingest_validator(app, {**config, 'trust_schema': str(schema_path)})

    int_name, sig_ptrs = signed_command('/repo/ingest', _CommandSigner(producer_signer))
    assert validate(validator, int_name, sig_ptrs)
    int_name, sig_ptrs = signed_command('/other-repo/ingest', _CommandSigner(producer_signer))
    assert not validate(validator, int_name, sig_ptrs)


def test_ingest_validator_rejects_name_outside_schema(pki):
    app, config, producer_signer, _, _ = pki
    validator = create_ingest_validator(app, config)

    int_name, sig_ptrs = signed_command('/other-repo/ingest', _CommandSigner(producer_signer))
    assert not validate(validator, int_name, sig_ptrs)


def test_ingest_validator_rejects_untrusted_signer(pki):
    app, config, _, _, unauthorized_producer = pki
    validator = create_ingest_validator(app, config)

    # This producer has a valid chain to the configured anchor, but its name is
    # not authorized by the LVS schema.
    int_name, sig_ptrs = signed_command('/repo/ingest', _CommandSigner(unauthorized_producer))
    assert not validate(validator, int_name, sig_ptrs)

    # Self-signed key with a producer-like name, not certified by the trust anchor
    key_name, _, priv = make_key('/producer-a/KEY')
    attacker = Sha256WithEcdsaSigner(key_name + [Component.from_str('self'), Component.from_version(1)], priv)
    int_name, sig_ptrs = signed_command('/repo/ingest', _CommandSigner(attacker))
    assert not validate(validator, int_name, sig_ptrs)

    # Digest signature has no KeyLocator
    int_name, sig_ptrs = signed_command('/repo/ingest', DigestSha256Signer(for_interest=True))
    assert not validate(validator, int_name, sig_ptrs)


def test_ingest_rejects_command_without_signature_time_or_nonce(pki, monkeypatch):
    _, _, producer_signer, _, _ = pki
    app = Mock()
    handle = DirectIngestHandle(app, Mock(), {}, Mock(), interest_validator=Mock(), keychain=Mock())
    # Rejected commands are answered synchronously, without creating a task
    create_task = Mock()
    monkeypatch.setattr(aio, 'create_task', create_task)
    reply = Mock()

    int_name, sig_ptrs = signed_command('/repo/ingest', producer_signer)
    handle._on_insert_interest(int_name, b'', reply, command_context(sig_ptrs))
    app.make_data.assert_called_once_with(int_name, None, handle.signer, content_type=ContentType.NACK)
    reply.assert_called_once_with(app.make_data.return_value)

    app.make_data.reset_mock()
    reply.reset_mock()
    handle._on_insert_interest(int_name, b'', reply, command_context(None))
    app.make_data.assert_called_once_with(int_name, None, handle.signer, content_type=ContentType.NACK)
    reply.assert_called_once_with(app.make_data.return_value)

    app.make_data.reset_mock()
    reply.reset_mock()
    int_name, sig_ptrs = signed_command('/repo/ingest', _CommandSigner(producer_signer))
    handle._on_insert_interest(int_name, b'\xff\xff', reply, command_context(sig_ptrs))
    app.make_data.assert_called_once_with(int_name, None, handle.signer, content_type=ContentType.NACK)
    reply.assert_called_once_with(app.make_data.return_value)
    create_task.assert_not_called()


def test_ingest_replies_are_signed_by_repo():
    app = Mock()
    repo_signer = Mock()
    keychain = Mock()
    keychain.get_signer.return_value = repo_signer
    handle = DirectIngestHandle(app, Mock(), {}, Mock(), interest_validator=Mock(), keychain=keychain)
    assert handle.signer is repo_signer

    # end_block_id < start_block_id is malformed: NACK without fetching
    param = ObjParam()
    param.name = Name.from_str('/data')
    param.start_block_id = 2
    param.end_block_id = 1
    int_name = Name.from_str('/repo/ingest')
    reply = Mock()
    aio.run(handle._process_insert(int_name, InterestParam(lifetime=10000), param, reply))
    app.express.assert_not_called()
    app.make_data.assert_called_once_with(int_name, None, repo_signer, content_type=ContentType.NACK)
    reply.assert_called_once_with(app.make_data.return_value)


def test_ingest_route_is_not_registered_without_validator():
    app = Mock()
    app.register = AsyncMock()
    handle = DirectIngestHandle(app, Mock(), {}, Mock())

    aio.run(handle.listen(Name.from_str('/repo')))

    app.register.assert_not_awaited()
    app.attach_handler.assert_not_called()


def test_ingest_route_uses_configured_validator():
    app = Mock()
    app.register = AsyncMock()
    validator = AsyncMock(return_value=ValidResult.FAIL)
    handle = DirectIngestHandle(app, Mock(), {}, Mock(), interest_validator=validator, keychain=Mock())

    aio.run(handle.listen(Name.from_str('/repo')))

    ingest_prefix = Name.from_str('/repo/ingest')
    app.attach_handler.assert_called_once_with(ingest_prefix, handle._on_insert_interest,
                                               handle._validate_command)
    app.register.assert_awaited_once_with(ingest_prefix)

    # Signed commands are checked by the configured validator
    int_name, sig_ptrs = signed_command('/repo/ingest', DigestSha256Signer(for_interest=True))
    assert aio.run(handle._validate_command(int_name, sig_ptrs, {})) == ValidResult.FAIL
    validator.assert_awaited_once_with(int_name, sig_ptrs, {})

    # Unsigned commands reach the handler, which NACKs them
    int_name, sig_ptrs = signed_command('/repo/ingest', None)
    assert aio.run(handle._validate_command(int_name, sig_ptrs, {})) == ValidResult.ALLOW_BYPASS
    validator.assert_awaited_once()
