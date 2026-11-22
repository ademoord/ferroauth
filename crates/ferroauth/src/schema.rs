//! Declarative database schema: four core tables (`user`, `session`,
//! `account`, `verification`) with camelCase columns. Plugins and
//! `user.additional_fields` extend it.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    String,
    Integer,
    Boolean,
    /// Stored as an RFC 3339 string with millisecond precision (`2026-01-01T00:00:00.000Z`).
    Date,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    pub model: String,
    pub field: String,
    pub on_delete_cascade: bool,
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub ty: FieldType,
    pub required: bool,
    pub unique: bool,
    pub index: bool,
    pub references: Option<Reference>,
    /// Whether clients may set this field (sign-up body, update-user body).
    pub input: bool,
    /// Whether this field is included in API responses.
    pub returned: bool,
    /// Value written on create when the field is absent.
    pub default_value: Option<serde_json::Value>,
}

impl Field {
    pub fn new(name: impl Into<String>, ty: FieldType) -> Self {
        Self {
            name: name.into(),
            ty,
            required: true,
            unique: false,
            index: false,
            references: None,
            input: false,
            returned: true,
            default_value: None,
        }
    }
    pub fn string(name: impl Into<String>) -> Self {
        Self::new(name, FieldType::String)
    }
    pub fn boolean(name: impl Into<String>) -> Self {
        Self::new(name, FieldType::Boolean)
    }
    pub fn integer(name: impl Into<String>) -> Self {
        Self::new(name, FieldType::Integer)
    }
    pub fn date(name: impl Into<String>) -> Self {
        Self::new(name, FieldType::Date)
    }
    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }
    pub fn unique(mut self) -> Self {
        self.unique = true;
        self
    }
    pub fn index(mut self) -> Self {
        self.index = true;
        self
    }
    pub fn input(mut self) -> Self {
        self.input = true;
        self
    }
    pub fn hidden(mut self) -> Self {
        self.returned = false;
        self
    }
    pub fn default(mut self, value: impl Into<serde_json::Value>) -> Self {
        self.default_value = Some(value.into());
        self
    }
    pub fn references(mut self, model: &str, field: &str) -> Self {
        self.references = Some(Reference { model: model.into(), field: field.into(), on_delete_cascade: true });
        self.index = true;
        self
    }
}

/// A table. Every table has an implicit string primary key named `id`.
#[derive(Clone, Debug)]
pub struct Table {
    pub name: String,
    pub fields: Vec<Field>,
}

impl Table {
    pub fn new(name: impl Into<String>, fields: Vec<Field>) -> Self {
        Self { name: name.into(), fields }
    }
    pub fn field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }
    /// Column type of `name`, including the implicit `id`.
    pub fn field_type(&self, name: &str) -> Option<FieldType> {
        if name == "id" {
            return Some(FieldType::String);
        }
        self.field(name).map(|f| f.ty)
    }
    /// All column names, `id` first.
    pub fn columns(&self) -> impl Iterator<Item = &str> {
        std::iter::once("id").chain(self.fields.iter().map(|f| f.name.as_str()))
    }
}

#[derive(Clone, Debug, Default)]
pub struct Schema {
    pub tables: Vec<Table>,
}

pub const USER: &str = "user";
pub const SESSION: &str = "session";
pub const ACCOUNT: &str = "account";
pub const VERIFICATION: &str = "verification";

impl Schema {
    pub fn new(tables: Vec<Table>) -> Self {
        Self { tables }
    }

    /// The core schema.
    pub fn core() -> Self {
        Self::new(vec![
            Table::new(
                USER,
                vec![
                    Field::string("name"),
                    Field::string("email").unique(),
                    Field::boolean("emailVerified"),
                    Field::string("image").optional(),
                    Field::date("createdAt"),
                    Field::date("updatedAt"),
                ],
            ),
            Table::new(
                SESSION,
                vec![
                    Field::date("expiresAt"),
                    Field::string("token").unique(),
                    Field::date("createdAt"),
                    Field::date("updatedAt"),
                    Field::string("ipAddress").optional(),
                    Field::string("userAgent").optional(),
                    Field::string("userId").references(USER, "id"),
                ],
            ),
            Table::new(
                ACCOUNT,
                vec![
                    Field::string("accountId"),
                    Field::string("providerId"),
                    Field::string("userId").references(USER, "id"),
                    Field::string("accessToken").optional().hidden(),
                    Field::string("refreshToken").optional().hidden(),
                    Field::string("idToken").optional().hidden(),
                    Field::date("accessTokenExpiresAt").optional(),
                    Field::date("refreshTokenExpiresAt").optional(),
                    Field::string("scope").optional(),
                    Field::string("password").optional().hidden(),
                    Field::date("createdAt"),
                    Field::date("updatedAt"),
                ],
            ),
            Table::new(
                VERIFICATION,
                vec![
                    Field::string("identifier").index(),
                    Field::string("value"),
                    Field::date("expiresAt"),
                    Field::date("createdAt"),
                    Field::date("updatedAt"),
                ],
            ),
        ])
    }

    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables.iter().find(|t| t.name == name)
    }

    /// Merge `other` into `self`: new tables are appended, fields of existing
    /// tables are added (fields with a name that already exists are replaced).
    pub fn merge(&mut self, other: Schema) {
        for table in other.tables {
            match self.tables.iter_mut().find(|t| t.name == table.name) {
                Some(existing) => {
                    for field in table.fields {
                        if let Some(slot) = existing.fields.iter_mut().find(|f| f.name == field.name) {
                            *slot = field;
                        } else {
                            existing.fields.push(field);
                        }
                    }
                }
                None => self.tables.push(table),
            }
        }
    }

    /// Convenience for plugins that only add fields to one table.
    pub fn extend_table(table: &str, fields: Vec<Field>) -> Self {
        Self::new(vec![Table::new(table, fields)])
    }
}
