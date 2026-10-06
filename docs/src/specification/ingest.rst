.. _specification-ingest-label:

Ingest
======

The direct ingest protocol is a lightweight command/response alternative to :doc:`insert`,
for high-throughput producers. It does not use :doc:`../misc_pkgs/pub_sub`: the repo listens
for Interests directly, and each command is a single Interest/Data exchange.

1. The repo registers an Interest filter on ``/<repo_name>/ingest``.

2. The producer sends an Interest under ``/<repo_name>/ingest`` carrying an ``ObjParam``
   as its application parameters. NDN appends a ``params-sha256=<digest>`` component computed
   over the parameter, so the Interest name reflects its command parameters, with the
   following fields:

   * ``name``: either a Data packet name, or a name prefix of segmented Data packets.
   * ``forwarding_hint`` (Optional): forwarding hint used to fetch ``name``, same
     semantics as in :doc:`insert`.
   * ``start_block_id`` (Optional): inclusive start segment number.
   * ``end_block_id`` (Optional): inclusive end segment number.
   * ``register_prefix`` (Optional): tell the repo to start serving reads under this prefix
     once the data is stored.

   See :doc:`encoding` for the ``ObjParam`` ABNF and TLV-TYPE assignments.

3. The repo fetches and stores Data following the same rules as :doc:`insert`:

   * If neither block id is given, the repo fetches the single packet identified by
     ``name``.
   * If only ``end_block_id`` is given, ``start_block_id`` is considered 0.
   * If only ``start_block_id`` is given, ``end_block_id`` is auto-detected, i.e. infinity.
   * If both are given, the command is valid only when ``end_block_id >= start_block_id``.
   * Segment numbers follow `NDN naming conventions rev3
     <https://named-data.net/publications/techreports/ndn-tr-22-3-ndn-memo-naming-conventions/>`_.

4. Once all requested packets are fetched and stored, the repo acks by replying to the
   original ingest Interest with an empty Data packet.

5. If the command fails, the repo replies to the original ingest Interest with an empty
   Data packet whose ``ContentType`` is ``NACK``. The producer may resend the command to
   retry. There is no status/check protocol for ingest (contrast with :doc:`check`, available
   for :doc:`insert` and :doc:`delete`).

The repo must reply before the ingest Interest expires, so fetching is bounded by its
``InterestLifetime``; if fetching does not finish in time, the repo replies with a NACK.
Ingest commands are idempotent, so resending a command is safe.

.. note::
   ``register_prefix`` registrations are kept only in memory, not persisted like
   :doc:`insert`, and are lost on repo restart. Also, unlike :doc:`insert`, the repo does not
   check whether ``name`` overlaps with its own ``/<repo_name>`` namespace.
