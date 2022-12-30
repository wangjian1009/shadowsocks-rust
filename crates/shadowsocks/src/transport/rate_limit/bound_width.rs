use std::{
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

use lazy_static::lazy_static;

use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

use regex::Regex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Duration {
    S,
}

impl Display for Duration {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self {
            Self::S => write!(f, "b/s"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundWidth {
    amount: u32,
    duration: Duration,
}

impl BoundWidth {
    pub fn as_bps(&self) -> u32 {
        match &self.duration {
            &Duration::S => self.amount,
        }
    }

    pub fn bps(amount: u32) -> Option<Self> {
        Some(BoundWidth {
            amount,
            duration: Duration::S,
        })
    }
}

impl FromStr for BoundWidth {
    type Err = fmt::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        lazy_static! {
            static ref RE: Regex = Regex::new(r"^([\d\.]+)([kKmMgG]?)((:?b[p/]s)?)$").unwrap();
        }

        match RE.captures(s) {
            Some(values) => {
                let mut num: f32 = match values[1].parse() {
                    Ok(r) => r,
                    Err(..) => return Err(fmt::Error),
                };

                if &values[2] == "k" || &values[2] == "K" {
                    num *= 1024.0;
                } else if &values[2] == "m" || &values[2] == "M" {
                    num *= 1024.0 * 1024.0;
                } else if &values[2] == "g" || &values[2] == "G" {
                    num *= 1024.0 * 1024.0 * 1024.0;
                }

                Ok(BoundWidth {
                    amount: num as u32,
                    duration: Duration::S,
                })
            }
            None => Err(fmt::Error),
        }
    }
}

impl Serialize for BoundWidth {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(format!("{}", self).as_str())
    }
}

struct BoundWidthVisitor;

impl<'de> Visitor<'de> for BoundWidthVisitor {
    type Value = BoundWidth;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("an nonzero integer for bps or Kb/s, Nb/s, Gb/s as unit")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match BoundWidth::from_str(value) {
            Ok(r) => Ok(r),
            Err(err) => Err(E::custom(format!("{}", err))),
        }
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(BoundWidth {
            amount: v as u32,
            duration: Duration::S,
        })
    }
}

impl<'de> Deserialize<'de> for BoundWidth {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(BoundWidthVisitor)
    }
}

impl Display for BoundWidth {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let v: u32 = self.amount;
        if v < 1024 {
            return write!(f, "{}{}", v, self.duration);
        }

        let v = v as f32 / 1024.0;
        if v < 1024.0 {
            return write!(f, "{}K{}", v, self.duration);
        }

        let v = v / 1024.0;
        if v < 1024.0 {
            return write!(f, "{:.2}M{}", v, self.duration);
        }

        let v = v / 1024.0;
        write!(f, "{:.2}G{}", v, self.duration)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn to_string() {
        assert_eq!(format!("{}", BoundWidth::bps(32).unwrap()), "32b/s");
        assert_eq!(format!("{}", BoundWidth::bps(1024).unwrap()), "1Kb/s");
        assert_eq!(format!("{}", BoundWidth::bps((1024 + 300) * 1024).unwrap()), "1.29Mb/s");
        assert_eq!(
            format!("{}", BoundWidth::bps((1024 + 300) * 1024 * 1024).unwrap()),
            "1.29Gb/s"
        );
    }

    #[test]
    fn from_string() {
        assert_eq!(BoundWidth::from_str("32").unwrap().as_bps(), 32u32);
        assert_eq!(BoundWidth::from_str("32bps").unwrap().as_bps(), 32u32);
        assert_eq!(BoundWidth::from_str("32b/s").unwrap().as_bps(), 32u32);
        assert_eq!(BoundWidth::from_str("32k").unwrap().as_bps(), 32u32 * 1024u32);
        assert_eq!(BoundWidth::from_str("32kbps").unwrap().as_bps(), 32u32 * 1024u32);
        assert_eq!(BoundWidth::from_str("32Kbps").unwrap().as_bps(), 32u32 * 1024u32);
        assert_eq!(BoundWidth::from_str("32m").unwrap().as_bps(), 32u32 * 1024u32 * 1024u32);
        assert_eq!(
            BoundWidth::from_str("32mbps").unwrap().as_bps(),
            32u32 * 1024u32 * 1024u32
        );
        assert_eq!(
            BoundWidth::from_str("32Mbps").unwrap().as_bps(),
            32u32 * 1024u32 * 1024u32
        );
        assert_eq!(
            BoundWidth::from_str("2gbps").unwrap().as_bps(),
            2u32 * 1024u32 * 1024u32 * 1024u32
        );
        assert_eq!(
            BoundWidth::from_str("2Gbps").unwrap().as_bps(),
            2u32 * 1024u32 * 1024u32 * 1024u32
        );
    }

    #[test]
    fn to_json() {
        use serde_json;

        let bound_width = BoundWidth::from_str("32k").unwrap();
        assert_eq!(serde_json::to_string(&bound_width).unwrap(), "\"32Kb/s\"");
    }

    #[test]
    fn from_json() {
        use serde_json;

        let bound_width: BoundWidth = serde_json::from_str("\"32Kb/s\"").unwrap();
        assert_eq!(bound_width.as_bps(), 32u32 * 1024u32);
    }
}
