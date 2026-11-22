"""Byte accounting from the actual encoders, without implementing a decoder.

Parts are disjoint, including every repeated Head/signature and framing byte.
Named nested representations (source/certificate/path/event) include their own
internal framing. The remaining framing field covers only unassigned wrappers.
"""
from regabe import primitives as a, core as c
from . import protocol as p


def checked_parts(total, parts):
    parts = dict(parts)
    remainder = total - sum(parts.values())
    if remainder < 0 or any(type(v) is not int or v < 0 for v in parts.values()):
        raise ValueError('invalid or overlapping encoded byte components')
    return {**parts, 'framing_bytes': remainder, 'total_bytes': total}


def registration_parts(sp, record):
    private = isinstance(record, a.Registration)
    cert = record.certificate if private else record.cert
    parts = {'source_bytes': len(a.registration_source_wire(record.source_public)),
             'certificate_bytes': len(cert.message()) + len(cert.signature),
             'metadata_bytes': len(b'SUPPLEMENT-PRIVATE-v1' if private else b'SUPPLEMENT-PUBLIC-v1')
                               + len(sp.ctx.pp_id) + len(sp.ctx.schema_id),
             'public_profile_bytes': 0, 'commitment_bytes': 0,
             'X_bytes': 0, 'Y_bytes': 0, 'proof_bytes': 0}
    if private:
        parts.update(commitment_bytes=len(a.pbytes_g1(record.C)),
                     X_bytes=sum(len(a.pbytes_g1(x)) for x in record.X),
                     Y_bytes=sum(len(a.pbytes_g2(y)) for ys in record.Y.values() for y in ys),
                     proof_bytes=sum(len(a.pbytes_g1(d)) for d in record.splits)
                       + len(a.scalar_bytes(record.challenge))
                       + sum(len(a.scalar_bytes(z)) for row in record.responses for z in row))
    else:
        parts['public_profile_bytes'] = len(bytes(record.bits))
    return checked_parts(len(record.wire(sp)), parts)


def path_wire(path):
    return c.seq([a.i2b(path.index, 4), a.i2b(path.count, 4), *path.siblings])


def _event_parts(descriptor):
    metadata = len(descriptor.old_descriptor) + len(descriptor.new_descriptor)
    if isinstance(descriptor, c.Manifest):
        metadata += len(descriptor.delta_root) + len(descriptor.vector_digest)
    else:
        metadata += len(b'SUPPLEMENT-PUBLIC-TARGET-v1') + 4
    return {'event_bytes': len(descriptor.event.wire()), 'manifest_metadata_bytes': metadata}


def response_parts(material):
    full = isinstance(material, c.SyncInput)
    receipt = material.commit
    common = _event_parts(material.manifest if full else material.notice)
    client = {**common, 'head_bytes': len(receipt.head.wire()),
              'signature_bytes': len(receipt.auth.ra) + len(receipt.auth.kc) + len(receipt.auth.board),
              'common_correction_bytes': 0, 'own_correction_bytes': 0, 'paths_bytes': 0}
    if full:
        client.update(common_correction_bytes=len(a.pbytes_g1(material.du)),
                      own_correction_bytes=len(a.pbytes_g2(material.own_delta)),
                      paths_bytes=len(path_wire(material.common_path)) + len(path_wire(material.own_path)))
    total = len(p.full_sync_wire(material) if full else material.wire())
    return checked_parts(total, client)


def update_parts(packet, receipt, material):
    full = isinstance(packet, c.Update)
    common = _event_parts(packet.manifest if full else packet)
    pub = {**common, 'head_bytes': len(packet.head.wire()) + len(receipt.head.wire()),
           'signature_bytes': len(packet.ra_signature) + len(receipt.auth.ra)
                            + len(receipt.auth.kc) + len(receipt.auth.board),
           'common_correction_bytes': 0, 'user_corrections_bytes': 0,
           'coordinate_metadata_bytes': 0}
    if full:
        pub['common_correction_bytes'] = len(a.pbytes_g1(packet.du))
        pub['user_corrections_bytes'] = sum(len(a.pbytes_g2(x)) for x in packet.dw)
        pub['coordinate_metadata_bytes'] = sum(len(x) for x in c.delta_payload(packet.manifest.event, packet.du, packet.dw)) \
            - pub['common_correction_bytes'] - pub['user_corrections_bytes']
    pub_total = len(c.seq([packet.canonical(), p.receipt_wire(receipt)]))
    return checked_parts(pub_total, pub), response_parts(material)


def sum_parts(rows):
    rows = list(rows)
    if not rows:
        return {}
    keys = set(rows[0])
    if any(set(row) != keys for row in rows):
        raise ValueError('incompatible byte component schemas')
    result = {key: sum(row[key] for row in rows) for key in rows[0]}
    if sum(v for key, v in result.items() if key != 'total_bytes') != result['total_bytes']:
        raise ValueError('byte component sum mismatch')
    return result
