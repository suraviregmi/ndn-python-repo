.. _specification-ingest-label:

Ingest
======

The direct ingest protocol is a lightweight command/response alternative to :doc:`insert`,
for high-throughput producers. It does not use :doc:`../misc_pkgs/pub_sub`: the repo listens
for Interests directly, and each command is a single Interest/Data exchange.

1. The repo registers an Interest filter on ``/<repo_name>/ingest``.

2. The producer sends a signed Interest under ``/<repo_name>/ingest`` carrying an ``ObjParam``
   as its application parameters. The InterestSignatureInfo must contain ``SignatureTime``
   and ``SignatureNonce``. Since the ``params-sha256=<digest>`` name component covers both the
   parameters and the signature, every command Interest has a distinct name, even when it
   carries the same parameters as an earlier one. ``ObjParam`` has the following fields:

   * ``name``: either a Data packet name, or a name prefix of segmented Data packets.
   * ``forwarding_hint`` (Optional): forwarding hint used to fetch ``name``, same
     semantics as in :doc:`insert`.
   * ``start_block_id`` (Optional): inclusive start segment number.
   * ``end_block_id`` (Optional): inclusive end segment number.
   * ``register_prefix`` (Optional): tell the repo to start serving reads under this prefix
     once the data is stored.

   See :doc:`encoding` for the ``ObjParam`` ABNF and TLV-TYPE assignments.

3. The repo fetches and stores Data as in step 3 of :doc:`insert`.

4. Once all requested packets are fetched and stored, the repo acks by replying to the
   original ingest Interest with an empty Data packet.

5. If the command fails, the repo replies to the original ingest Interest with an empty
   Data packet whose ``ContentType`` is ``NACK``. The producer may retry by sending the
   command again as a new signed Interest, which has a new name. There is no status/check
   protocol for ingest (contrast with :doc:`check`, available for :doc:`insert` and
   :doc:`delete`).

The repo must reply before the ingest Interest expires, so fetching is bounded by its
``InterestLifetime``; if fetching does not finish in time, the repo replies with a NACK.
Ingest commands are idempotent, so resending a command is safe.

.. note::
   ``register_prefix`` registrations are kept only in memory, not persisted like
   :doc:`insert`, and are lost on repo restart. Also, unlike :doc:`insert`, the repo does not
   check whether ``name`` overlaps with its own ``/<repo_name>`` namespace.
   The repo does not yet validate the command Interest's signature against a trust schema.
