// Package protocheck validates method payloads against authoritative protobuf
// descriptors before bytes cross a Provider boundary.
//
// The package is deliberately stateless. Catalog selection, permission checks,
// leases, deadlines, route ownership, and Transfer ticket ownership remain
// kernel responsibilities. This package only validates and canonicalizes the
// protobuf value selected by an already-authorized MethodMeta.
package protocheck
