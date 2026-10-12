package scim

// The discovery documents (RFC 7644 §4): what the hub supports, which resource
// types it serves, and the schemas they follow. An identity provider reads
// them to decide what to send — Entra ID's validator generates its test users
// from /Schemas — so they say exactly what the hub does and no more: no bulk,
// no sort, no password change.

import "strings"

// DocumentationURI is where an operator reads how provisioning works on the
// hub.
const DocumentationURI = "https://blechschmidt.github.io/cloop/docs/guides/scim-provisioning/"

// ServiceProviderConfig is the /ServiceProviderConfig document for a hub whose
// SCIM base URL is base.
func ServiceProviderConfig(base string) map[string]any {
	return map[string]any{
		"schemas":          []string{SchemaServiceProviderConfig},
		"documentationUri": DocumentationURI,
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": MaxPageSize},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": true},
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken",
			"name": "SCIM bearer credential",
			"description": "A cloop_scim_ credential minted for this identity provider with " +
				"`cloop hub scim credential create` or under Settings → Provisioning (SCIM). It is " +
				"accepted on these routes only.",
			"specUri":          "https://www.rfc-editor.org/info/rfc6750",
			"documentationUri": DocumentationURI,
			"primary":          true,
		}},
		"meta": map[string]any{
			"resourceType": "ServiceProviderConfig",
			"location":     strings.TrimSuffix(base, "/") + "/ServiceProviderConfig",
		},
	}
}

// ResourceTypes are the /ResourceTypes documents, by id.
func ResourceTypes(base string) []map[string]any {
	base = strings.TrimSuffix(base, "/")
	return []map[string]any{
		{
			"schemas":     []string{SchemaResourceType},
			"id":          "User",
			"name":        "User",
			"endpoint":    "/Users",
			"description": "A person provisioned by the identity provider.",
			"schema":      SchemaUser,
			"schemaExtensions": []map[string]any{
				{"schema": SchemaEnterpriseUser, "required": false},
			},
			"meta": map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/User"},
		},
		{
			"schemas":     []string{SchemaResourceType},
			"id":          "Group",
			"name":        "Group",
			"endpoint":    "/Groups",
			"description": "A group provisioned by the identity provider.",
			"schema":      SchemaGroup,
			"meta":        map[string]any{"resourceType": "ResourceType", "location": base + "/ResourceTypes/Group"},
		},
	}
}

// Schemas are the /Schemas documents.
func Schemas(base string) []map[string]any {
	base = strings.TrimSuffix(base, "/")
	var out []map[string]any
	for _, s := range []Schema{UserSchema, EnterpriseUserSchema, GroupSchema} {
		out = append(out, map[string]any{
			"schemas":     []string{SchemaSchema},
			"id":          s.ID,
			"name":        s.Name,
			"description": s.Description,
			"attributes":  s.Attributes,
			"meta":        map[string]any{"resourceType": "Schema", "location": base + "/Schemas/" + s.ID},
		})
	}
	return out
}

// FindByID returns the document whose id is id, case-insensitively.
func FindByID(docs []map[string]any, id string) (map[string]any, bool) {
	for _, d := range docs {
		if s, _ := d["id"].(string); strings.EqualFold(s, id) {
			return d, true
		}
	}
	return nil, false
}
