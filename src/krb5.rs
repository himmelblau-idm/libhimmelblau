use crate::auth::AesKey;
use crate::error::MsalError;
use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use himmelblau_kerberos_ccache::{
    CCache as HKCCache, CountedOctetString, Credential, Header, KeyBlock, Principal, Times,
};
use picky_asn1::wrapper::{
    GeneralizedTimeAsn1 as GeneralizedTimeAsn1In, IntegerAsn1 as IntegerAsn1In,
};
use picky_krb::messages::{AsRep, EncAsRepPart};
use std::fs::OpenOptions;
use std::io::Write;

pub(crate) struct IntegerAsn1<'a>(pub(crate) &'a IntegerAsn1In);
impl TryFrom<IntegerAsn1<'_>> for u16 {
    type Error = MsalError;

    fn try_from(i: IntegerAsn1) -> Result<Self, Self::Error> {
        if i.0.len() == 1 {
            Ok(i.0[0] as u16)
        } else if i.0.len() == 2 {
            Ok(u16::from_be_bytes(
                i.0.as_unsigned_bytes_be()[0..2]
                    .try_into()
                    .map_err(|e| MsalError::FormatError(format!("{:?}", e)))?,
            ))
        } else {
            Err(MsalError::FormatError(format!(
                "Failed formatting {} byte IntegerAsn1 as u16",
                i.0.len()
            )))
        }
    }
}
impl TryFrom<IntegerAsn1<'_>> for u32 {
    type Error = MsalError;

    fn try_from(i: IntegerAsn1) -> Result<Self, Self::Error> {
        if i.0.len() == 1 {
            Ok(i.0[0] as u32)
        } else if i.0.len() == 4 {
            Ok(u32::from_be_bytes(
                i.0.as_unsigned_bytes_be()[0..4]
                    .try_into()
                    .map_err(|e| MsalError::FormatError(format!("{:?}", e)))?,
            ))
        } else {
            Err(MsalError::FormatError(format!(
                "Failed formatting {} byte IntegerAsn1 as u32",
                i.0.len()
            )))
        }
    }
}

struct GeneralizedTimeAsn1(GeneralizedTimeAsn1In);
impl TryFrom<GeneralizedTimeAsn1> for u32 {
    type Error = MsalError;

    fn try_from(i: GeneralizedTimeAsn1) -> Result<u32, Self::Error> {
        let date = NaiveDate::from_ymd_opt(i.0.year().into(), i.0.month().into(), i.0.day().into())
            .ok_or(MsalError::FormatError("Invalid date specified".to_string()))?;
        let time =
            NaiveTime::from_hms_opt(i.0.hour().into(), i.0.minute().into(), i.0.second().into())
                .ok_or(MsalError::FormatError("Invalid time specified".to_string()))?;
        let instant = NaiveDateTime::new(date, time);
        // WARNING: This is susceptible to the year 2038 time problem!
        Ok(instant.and_utc().timestamp() as u32)
    }
}

pub(crate) struct FileCredentialCache {
    ccache: HKCCache,
}

impl FileCredentialCache {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.ccache.clone().build()
    }

    pub(crate) fn save_keytab_file(&self, filename: &str) -> Result<(), MsalError> {
        let bytes = self.ccache.clone().build();
        let mut keytab_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(filename)
            .map_err(|e| MsalError::GeneralFailure(format!("{:?}", e)))?;
        keytab_file
            .write_all(&bytes)
            .map_err(|e| MsalError::GeneralFailure(format!("{:?}", e)))?;
        keytab_file
            .sync_all()
            .map_err(|e| MsalError::GeneralFailure(format!("{:?}", e)))?;
        Ok(())
    }

    pub(crate) fn new(tgt: &AsRep, client_key: &AesKey) -> Result<Self, MsalError> {
        let header = Header::new(
            Header::DELTA_TIME,
            vec![0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
        );

        let principal = Principal::new(
            IntegerAsn1(&tgt.0.cname.name_type.0).try_into()?,
            CountedOctetString::new(tgt.0.crealm.0.as_bytes().to_vec()),
            tgt.0
                .cname
                .0
                .name_string
                .0
                .iter()
                .cloned()
                .map(|elm| CountedOctetString::new(elm.as_bytes().to_vec()))
                .collect(),
        );

        let cipher_text = tgt.0.enc_part.0.cipher.to_vec();
        let plain_text = client_key.decrypt(&cipher_text)?;
        let enc_part: EncAsRepPart = picky_asn1_der::from_bytes(&plain_text)
            .map_err(|e| MsalError::CryptoFail(format!("EncAsRepPart decode fail: {:?}", e)))?;

        let tktflags = enc_part.0.flags.0.as_bytes();
        let credential = Credential::new(
            principal.clone(),
            Principal::new(
                IntegerAsn1(&enc_part.0.sname.name_type.0).try_into()?,
                CountedOctetString::new(enc_part.0.srealm.0.as_bytes().to_vec()),
                enc_part
                    .0
                    .sname
                    .0
                    .name_string
                    .0
                    .iter()
                    .cloned()
                    .map(|elm| CountedOctetString::new(elm.as_bytes().to_vec()))
                    .collect(),
            ),
            KeyBlock::new(
                IntegerAsn1(&enc_part.0.key.key_type.0).try_into()?,
                enc_part.0.key.0.key_value.to_vec(),
            ),
            Times::new(
                GeneralizedTimeAsn1(enc_part.0.auth_time.0).try_into()?,
                match enc_part.0.start_time.0 {
                    Some(start_time) => GeneralizedTimeAsn1(start_time.0).try_into()?,
                    None => 0,
                },
                GeneralizedTimeAsn1(enc_part.0.end_time.0).try_into()?,
                match enc_part.0.renew_till.0 {
                    Some(renew_till) => GeneralizedTimeAsn1(renew_till.0).try_into()?,
                    None => 0,
                },
            ),
            0,
            u32::from_be_bytes([tktflags[3], tktflags[2], tktflags[1], tktflags[0]]),
            CountedOctetString::new(
                picky_asn1_der::to_vec(&tgt.0.ticket.0 .0)
                    .map_err(|e| MsalError::CryptoFail(format!("{:?}", e)))?,
            ),
        );

        let ccache = HKCCache::new(header, principal, vec![credential]);

        Ok(FileCredentialCache { ccache })
    }
}
