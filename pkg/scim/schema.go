package scim

// The attribute definitions the hub serves at /Schemas and reasons with.
//
// They do three jobs. Served, they tell an identity provider what to send.
// Read here, they decide how an attribute compares — userName is not
// case-exact, externalId is — which values are booleans even when Entra ID
// sends the string "False", which attributes are multi-valued, and which a
// client may not write. And they give each attribute its canonical spelling:
// attribute names are case-insensitive (RFC 7643 §2.1), so "UserName" and
// "userName" are one attribute, stored once.
//
// An attribute nobody defined — an identity provider's validator invents them
// — is not refused. It is stored and returned as sent, compared case-
// insensitively, and never decided on.

import "strings"

// Attribute is one attribute definition (RFC 7643 §7).
type Attribute struct {
	Name            string      `json:"name"`
	Type            string      `json:"type"`
	MultiValued     bool        `json:"multiValued"`
	Description     string      `json:"description,omitempty"`
	Required        bool        `json:"required"`
	CaseExact       bool        `json:"caseExact"`
	Mutability      string      `json:"mutability"`
	Returned        string      `json:"returned"`
	Uniqueness      string      `json:"uniqueness"`
	CanonicalValues []string    `json:"canonicalValues,omitempty"`
	ReferenceTypes  []string    `json:"referenceTypes,omitempty"`
	SubAttributes   []Attribute `json:"subAttributes,omitempty"`
}

// Schema is one schema definition.
type Schema struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Attributes  []Attribute `json:"attributes"`
}

// sub returns the named sub-attribute, case-insensitively.
func (a *Attribute) sub(name string) *Attribute {
	if a == nil {
		return nil
	}
	for i := range a.SubAttributes {
		if strings.EqualFold(a.SubAttributes[i].Name, name) {
			return &a.SubAttributes[i]
		}
	}
	return nil
}

// attr returns the named attribute of s, case-insensitively.
func (s *Schema) attr(name string) *Attribute {
	if s == nil {
		return nil
	}
	for i := range s.Attributes {
		if strings.EqualFold(s.Attributes[i].Name, name) {
			return &s.Attributes[i]
		}
	}
	return nil
}

func str(name, desc string) Attribute {
	return Attribute{Name: name, Type: "string", Description: desc, Mutability: "readWrite",
		Returned: "default", Uniqueness: "none"}
}

func boolean(name, desc string) Attribute {
	return Attribute{Name: name, Type: "boolean", Description: desc, Mutability: "readWrite",
		Returned: "default", Uniqueness: "none"}
}

func ref(name, desc string, types ...string) Attribute {
	return Attribute{Name: name, Type: "reference", Description: desc, Mutability: "readWrite",
		Returned: "default", Uniqueness: "none", CaseExact: true, ReferenceTypes: types}
}

// multi is a multi-valued complex attribute with the usual value, display,
// type and primary sub-attributes.
func multi(name, desc string, extra ...Attribute) Attribute {
	subs := []Attribute{str("value", "The attribute's value."), str("display", "A human-readable name."),
		str("type", "A label indicating the attribute's function."),
		boolean("primary", "The primary or preferred value of the attribute.")}
	subs = append(subs, extra...)
	return Attribute{Name: name, Type: "complex", MultiValued: true, Description: desc,
		Mutability: "readWrite", Returned: "default", Uniqueness: "none", SubAttributes: subs}
}

// UserSchema is the core User schema, as far as the hub reads and returns it.
var UserSchema = Schema{
	ID: SchemaUser, Name: "User", Description: "A person provisioned by the identity provider.",
	Attributes: []Attribute{
		{Name: "userName", Type: "string", Required: true, Mutability: "readWrite", Returned: "always",
			Uniqueness: "server", Description: "The account's unique login, compared case-insensitively."},
		{Name: "name", Type: "complex", Mutability: "readWrite", Returned: "default", Uniqueness: "none",
			Description: "The components of the user's name.",
			SubAttributes: []Attribute{str("formatted", "The full name."), str("familyName", "The family name."),
				str("givenName", "The given name."), str("middleName", "The middle name."),
				str("honorificPrefix", "The honorific prefix."), str("honorificSuffix", "The honorific suffix.")}},
		str("displayName", "The name displayed to end users."),
		str("nickName", "The casual way to address the user."),
		ref("profileUrl", "A URI to the user's online profile.", "external"),
		str("title", "The user's title."),
		str("userType", "The relationship between the organisation and the user."),
		str("preferredLanguage", "The user's preferred written or spoken language."),
		str("locale", "The user's default location for localisation."),
		str("timezone", "The user's time zone."),
		{Name: "active", Type: "boolean", Mutability: "readWrite", Returned: "default", Uniqueness: "none",
			Description: "Whether the account may act. false suspends it on the hub: its sessions, API tokens, " +
				"glasses links, leases and running tasks end, and a deny binding refuses it everywhere."},
		{Name: "password", Type: "string", Mutability: "writeOnly", Returned: "never", Uniqueness: "none",
			Description: "Accepted and discarded: the hub authenticates people through single sign-on, " +
				"and never stores a password."},
		multi("emails", "Email addresses. The primary one, else the work one, is the account's email."),
		multi("phoneNumbers", "Phone numbers."),
		multi("ims", "Instant messaging addresses."),
		multi("photos", "URLs of photos of the user."),
		{Name: "addresses", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default",
			Uniqueness: "none", Description: "Physical mailing addresses.",
			SubAttributes: []Attribute{str("formatted", "The full address."), str("streetAddress", "The street."),
				str("locality", "The city or locality."), str("region", "The state or region."),
				str("postalCode", "The postal code."), str("country", "The country."),
				str("type", "A label indicating the address's function."),
				boolean("primary", "The primary address.")}},
		{Name: "groups", Type: "complex", MultiValued: true, Mutability: "readOnly", Returned: "default",
			Uniqueness: "none", Description: "The groups the user belongs to, maintained through the groups.",
			SubAttributes: []Attribute{
				{Name: "value", Type: "string", Mutability: "readOnly", Returned: "default", Uniqueness: "none",
					CaseExact: true, Description: "The group's id."},
				ref("$ref", "The group's URI.", "Group"),
				{Name: "display", Type: "string", Mutability: "readOnly", Returned: "default",
					Uniqueness: "none", Description: "The group's display name."},
				{Name: "type", Type: "string", Mutability: "readOnly", Returned: "default",
					Uniqueness: "none", Description: "direct", CanonicalValues: []string{"direct"}}}},
		multi("entitlements", "Entitlements."),
		multi("roles", "Roles. Stored and returned; they grant nothing on the hub — bind a provisioned group instead."),
		multi("x509Certificates", "Certificates."),
	},
}

// EnterpriseUserSchema is the enterprise User extension.
var EnterpriseUserSchema = Schema{
	ID: SchemaEnterpriseUser, Name: "EnterpriseUser", Description: "Enterprise attributes of a user.",
	Attributes: []Attribute{
		str("employeeNumber", "The user's number within the organisation."),
		str("costCenter", "The cost center."),
		str("organization", "The organisation."),
		str("division", "The division."),
		str("department", "The department."),
		{Name: "manager", Type: "complex", Mutability: "readWrite", Returned: "default", Uniqueness: "none",
			Description: "The user's manager.",
			SubAttributes: []Attribute{
				{Name: "value", Type: "string", Mutability: "readWrite", Returned: "default", Uniqueness: "none",
					CaseExact: true, Description: "The manager's id."},
				ref("$ref", "The manager's URI.", "User"),
				{Name: "displayName", Type: "string", Mutability: "readOnly", Returned: "default",
					Uniqueness: "none", Description: "The manager's display name."}}},
	},
}

// GroupSchema is the core Group schema.
var GroupSchema = Schema{
	ID: SchemaGroup, Name: "Group", Description: "A group provisioned by the identity provider. A role " +
		"binding naming it (claim: scim_group) grants its members a role on the hub.",
	Attributes: []Attribute{
		{Name: "displayName", Type: "string", Required: true, Mutability: "readWrite", Returned: "always",
			Uniqueness: "server", Description: "The group's name, unique on the hub, compared case-insensitively. " +
				"What a scim_group role binding names, or the externalId."},
		{Name: "members", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default",
			Uniqueness: "none", Description: "The group's members: provisioned users, by id.",
			SubAttributes: []Attribute{
				{Name: "value", Type: "string", Mutability: "immutable", Returned: "default", Uniqueness: "none",
					CaseExact: true, Description: "The member's id."},
				ref("$ref", "The member's URI.", "User"),
				{Name: "display", Type: "string", Mutability: "readOnly", Returned: "default",
					Uniqueness: "none", Description: "The member's display name."},
				{Name: "type", Type: "string", Mutability: "immutable", Returned: "default",
					Uniqueness: "none", Description: "User", CanonicalValues: []string{"User"}}}},
	},
}

// commonAttributes are the attributes every resource carries (RFC 7643 §3.1).
var commonAttributes = []Attribute{
	{Name: "id", Type: "string", CaseExact: true, Mutability: "readOnly", Returned: "always", Uniqueness: "server"},
	{Name: "externalId", Type: "string", CaseExact: true, Mutability: "readWrite", Returned: "default",
		Uniqueness: "none"},
	{Name: "meta", Type: "complex", Mutability: "readOnly", Returned: "default", Uniqueness: "none"},
	{Name: "schemas", Type: "reference", MultiValued: true, CaseExact: true, Mutability: "readWrite",
		Returned: "always", Uniqueness: "none"},
}

// Kind is a resource type the hub serves.
type Kind int

const (
	// KindUser is a provisioned user.
	KindUser Kind = iota
	// KindGroup is a provisioned group.
	KindGroup
)

func (k Kind) String() string {
	if k == KindGroup {
		return "Group"
	}
	return "User"
}

// coreSchema is the kind's core schema.
func (k Kind) coreSchema() *Schema {
	if k == KindGroup {
		return &GroupSchema
	}
	return &UserSchema
}

// extensions are the kind's extension schemas, by URN.
func (k Kind) extensions() []*Schema {
	if k == KindUser {
		return []*Schema{&EnterpriseUserSchema}
	}
	return nil
}

// definition returns the definition of a top-level attribute of kind k:
// a common attribute, or one of the core schema's.
func (k Kind) definition(name string) *Attribute {
	for i := range commonAttributes {
		if strings.EqualFold(commonAttributes[i].Name, name) {
			return &commonAttributes[i]
		}
	}
	return k.coreSchema().attr(name)
}

// extension returns the extension schema with this URN, case-insensitively.
func (k Kind) extension(urn string) *Schema {
	for _, s := range k.extensions() {
		if strings.EqualFold(s.ID, urn) {
			return s
		}
	}
	return nil
}

// knownURN reports whether urn is the kind's core schema or one of its
// extensions, and returns its canonical spelling.
func (k Kind) knownURN(urn string) (string, bool) {
	if strings.EqualFold(urn, k.coreSchema().ID) {
		return k.coreSchema().ID, true
	}
	if s := k.extension(urn); s != nil {
		return s.ID, true
	}
	return "", false
}
