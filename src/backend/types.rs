use std::fmt;
use std::fmt::Display;
use yubihsmrs::object::{ObjectAlgorithm, ObjectCapability, ObjectDescriptor, ObjectDomain, ObjectType};

#[derive(Clone, Debug)]
pub struct ObjectSpec {
    pub id: u16,
    pub object_type: ObjectType,
    pub label: String,
    pub algorithm: ObjectAlgorithm,
    pub domains: Vec<ObjectDomain>,
    pub capabilities: Vec<ObjectCapability>,
    pub delegated_capabilities: Vec<ObjectCapability>,
}

impl Display for ObjectSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut spec_str = String::new().to_owned();
        spec_str.push_str(format!("ID: 0x{:04x?}\n", self.id).as_str());
        spec_str.push_str(format!("Label: {:40}\n", self.label).as_str());
        spec_str.push_str(format!("Algorithm: {:24}\n", self.algorithm).as_str());

        let mut dom_str = String::new().to_owned();
        self.domains.iter().for_each(|domain| dom_str.push_str(format!("{},", domain).as_str()));
        dom_str.pop();
        spec_str.push_str(format!("Domains: {:40}\n", dom_str).as_str());

        let mut caps_str = String::new().to_owned();
        self.capabilities.iter().for_each(|cap| caps_str.push_str(format!("{:?},", cap).as_str()));
        caps_str.pop();
        spec_str.push_str(format!("Capabilities: {}\n", caps_str).as_str());

        if [ObjectType::AuthenticationKey, ObjectType::WrapKey, ObjectType::PublicWrapKey].contains(&self.object_type) {
            caps_str = String::new().to_owned();
            self.delegated_capabilities.iter().for_each(|cap| caps_str.push_str(format!("{:?},", cap).as_str()));
            caps_str.pop();
            spec_str.push_str(format!("Delegated capabilities: {}\n", caps_str).as_str());
        }
        write!(f, "{}", spec_str)
    }
}


impl ObjectSpec {
    pub fn new(
        id: u16,
        object_type: ObjectType,
        label: String,
        algorithm: ObjectAlgorithm,
        domains: Vec<ObjectDomain>,
        capabilities: Vec<ObjectCapability>,
        delegated_capabilities: Vec<ObjectCapability>,
    ) -> Self {
        Self {
            id,
            object_type,
            label,
            algorithm,
            domains,
            capabilities,
            delegated_capabilities,
        }
    }

    pub fn empty() -> Self {
        Self {
            id: 0,
            object_type: ObjectType::Any,
            label: String::new(),
            algorithm: ObjectAlgorithm::ANY,
            domains: vec![],
            capabilities: vec![],
            delegated_capabilities: vec![],
        }
    }
}

impl From<ObjectDescriptor> for ObjectSpec {
    fn from(spec: ObjectDescriptor) -> Self {
        ObjectSpec {
            id: spec.id,
            object_type: spec.object_type,
            label: spec.label,
            algorithm: spec.algorithm,
            domains: spec.domains,
            capabilities: spec.capabilities,
            delegated_capabilities: if spec.delegated_capabilities.is_some() {
                spec.delegated_capabilities.unwrap()
            } else {
                vec![]
            },
        }
    }
}

impl From<ObjectSpec> for ObjectDescriptor {
    fn from(spec: ObjectSpec) -> Self {
        let mut desc = ObjectDescriptor::new();
        desc.id = spec.id;
        desc.object_type = spec.object_type;
        desc.label = spec.label;
        desc.algorithm = spec.algorithm;
        desc.domains = spec.domains;
        desc.capabilities = spec.capabilities;
        desc.delegated_capabilities = if spec.delegated_capabilities.is_empty() {
            None
        } else {
            Some(spec.delegated_capabilities)
        };
        desc
    }
}




#[derive(Clone, Debug)]
pub struct ImportObjectSpec {
    pub object: ObjectSpec,
    pub data: Vec<Vec<u8>>,
}

impl ImportObjectSpec {
    pub fn new(object: ObjectSpec, object_data: Vec<Vec<u8>>) -> Self {
        Self { object, data: object_data }
    }

    pub fn empty() -> Self {
        Self {
            object: ObjectSpec::empty(),
            data: vec![],
        }
    }
}

#[derive(Clone, Debug)]
pub struct YhAlgorithm {
    pub algorithm: ObjectAlgorithm,
    pub label: &'static str,
    pub description: &'static str,
}
