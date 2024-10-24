use crate::{
    msgs::handshake::{DistinguishedName, DistinguishedNames},
    x509,
};

/// A trust anchor, commonly known as a "Root Certificate."
#[derive(Debug, Clone)]
pub struct OwnedTrustAnchor {
    subject: Vec<u8>,
    spki: Vec<u8>,
    name_constraints: Option<Vec<u8>>,
}

impl OwnedTrustAnchor {
    /// Get a `webpki::TrustAnchor` by borrowing the owned elements.
    pub(crate) fn to_trust_anchor(&self) -> webpki::TrustAnchor {
        webpki::TrustAnchor {
            subject: &self.subject,
            spki: &self.spki,
            name_constraints: self.name_constraints.as_deref(),
        }
    }

    /// Constructs an `OwnedTrustAnchor` from its components.
    ///
    /// `subject` is the subject field of the trust anchor.
    ///
    /// `spki` is the `subjectPublicKeyInfo` field of the trust anchor.
    ///
    /// `name_constraints` is the value of a DER-encoded name constraints to
    /// apply for this trust anchor, if any.
    pub fn from_subject_spki_name_constraints(
        subject: impl Into<Vec<u8>>,
        spki: impl Into<Vec<u8>>,
        name_constraints: Option<impl Into<Vec<u8>>>,
    ) -> Self {
        Self {
            subject: subject.into(),
            spki: spki.into(),
            name_constraints: name_constraints.map(|x| x.into()),
        }
    }
}

/// Errors that can occur during operations with RootCertStore
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum RootCertStoreError {
    #[error(transparent)]
    WebpkiError(#[from] webpki::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("Unexpected PEM certificate count. Expected 1 certificate, got {0}")]
    PemCertUnexpectedCount(usize),
}

/// A container for root certificates able to provide a root-of-trust
/// for connection authentication.
#[derive(Debug, Clone)]
pub struct RootCertStore {
    /// The list of roots.
    pub roots: Vec<OwnedTrustAnchor>,
}

impl RootCertStore {
    /// Make a new, empty `RootCertStore`.
    pub fn empty() -> Self {
        Self { roots: Vec::new() }
    }

    /// Return true if there are no certificates.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Say how many certificates are in the container.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Return the Subject Names for certificates in the container.
    pub fn subjects(&self) -> DistinguishedNames {
        let mut r = DistinguishedNames::new();

        for ota in &self.roots {
            let mut name = Vec::new();
            name.extend_from_slice(&ota.subject);
            x509::wrap_in_sequence(&mut name);
            r.push(DistinguishedName::new(name));
        }

        r
    }

    /// Add a single DER-encoded certificate to the store.
    pub fn add(&mut self, der: &crate::key::Certificate) -> Result<(), RootCertStoreError> {
        let ta = webpki::TrustAnchor::try_from_cert_der(&der.0)?;
        let ota = OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        );
        self.roots.push(ota);
        Ok(())
    }

    /// Adds a single PEM-encoded certificate to the store.
    pub fn add_pem(&mut self, pem: &str) -> Result<(), RootCertStoreError> {
        let mut certificates = rustls_pemfile::certs(&mut pem.as_bytes())?;

        if certificates.len() != 1 {
            return Err(RootCertStoreError::PemCertUnexpectedCount(
                certificates.len(),
            ));
        }

        self.add(&crate::key::Certificate(certificates.remove(0)))?;

        Ok(())
    }

    /// Adds all the given TrustAnchors `anchors`.  This does not
    /// fail.
    pub fn add_server_trust_anchors(
        &mut self,
        trust_anchors: impl Iterator<Item = OwnedTrustAnchor>,
    ) {
        self.roots.extend(trust_anchors)
    }

    /// Parse the given DER-encoded certificates and add all that can be parsed
    /// in a best-effort fashion.
    ///
    /// This is because large collections of root certificates often
    /// include ancient or syntactically invalid certificates.
    ///
    /// Returns the number of certificates added, and the number that were ignored.
    pub fn add_parsable_certificates(&mut self, der_certs: &[Vec<u8>]) -> (usize, usize) {
        let mut valid_count = 0;
        let mut invalid_count = 0;

        for der_cert in der_certs {
            match self.add(&crate::key::Certificate(der_cert.clone())) {
                Ok(_) => valid_count += 1,
                Err(_err) => invalid_count += 1,
            }
        }

        (valid_count, invalid_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const CA_PEM_CERT: &[u8] = include_bytes!("../testdata/cert-digicert.pem");

    #[test]
    fn test_add_pem_ok() {
        let pem = std::str::from_utf8(CA_PEM_CERT).unwrap();
        assert!(RootCertStore::empty().add_pem(pem).is_ok());
    }

    #[test]
    fn test_add_pem_err_bad_cert() {
        assert_eq!(
            RootCertStore::empty()
                .add_pem("bad pem")
                .err()
                .unwrap()
                .to_string(),
            "Unexpected PEM certificate count. Expected 1 certificate, got 0"
        );
    }

    #[test]
    fn test_add_pem_err_more_than_one_cert() {
        let pem1 = std::str::from_utf8(CA_PEM_CERT).unwrap();
        let pem2 = pem1;

        assert_eq!(
            RootCertStore::empty()
                .add_pem((pem1.to_owned() + pem2).as_str())
                .err()
                .unwrap()
                .to_string(),
            "Unexpected PEM certificate count. Expected 1 certificate, got 2"
        );
    }
}
