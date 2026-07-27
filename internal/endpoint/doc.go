// Package endpoint owns connection-scoped endpoint registration, resolution,
// binding, and routing. It consumes the same immutable catalog Snapshot as
// permission, resource, pkgregistry, and IPC method validation.
//
// Registration proves exact provider/component membership, schema identity,
// resource compatibility, and catalog generations. Resolution applies the
// interface-owned default selector and permission. Every Route revalidates the
// registration, interface, provider, resource, method, and permissions against
// one current Snapshot, so catalog replacement and runtime permission
// revocation take effect on the next call.
package endpoint
