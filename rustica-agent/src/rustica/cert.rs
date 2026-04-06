use super::error::{RefreshError, ServerError};
use super::{CertificateRequest, RusticaCert, Signatory};
use crate::{CertificateConfig, MtlsCredentials, RusticaServer};
use rcgen::{Certificate as X509Certificate, CertificateParams, KeyPair};
use sshcerts::Certificate;
use tokio::runtime::Handle;
use x509_parser::pem::parse_x509_pem;

use std::collections::HashMap;
use std::time::SystemTime;

impl RusticaServer {
    fn create_mtls_refresh_csr(&self, renewal_period: u64) -> Vec<u8> {
        let cert = match parse_x509_pem(self.mtls_cert.as_bytes()) {
            Ok((_, cert)) => cert,
            Err(e) => {
                warn!("Could not parse mTLS cert PEM for CSR renewal window check, skipping CSR generation: {e}");
                return vec![];
            }
        };

        let expiry_timestamp = match cert.parse_x509() {
            Ok(cert) => cert.validity().not_after.timestamp(),
            Err(e) => {
                warn!("Could not parse mTLS cert for CSR renewal window check, skipping CSR generation: {e}");
                return vec![];
            }
        };

        let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(ts) => ts.as_secs(),
            Err(_) => return vec![],
        };

        if current_timestamp.saturating_add(renewal_period) < expiry_timestamp as u64 {
            return vec![];
        }

        let mut params = CertificateParams::new(vec![]);
        let key_pair = match KeyPair::from_pem(&self.mtls_key) {
            Ok(key_pair) => key_pair,
            Err(e) => {
                warn!("Could not parse mTLS key for CSR generation, falling back to legacy renewal flow: {e}");
                return vec![];
            }
        };

        params.alg = key_pair.algorithm();
        params.key_pair = Some(key_pair);

        let certificate = match X509Certificate::from_params(params) {
            Ok(certificate) => certificate,
            Err(e) => {
                warn!("Could not build mTLS CSR request, falling back to legacy renewal flow: {e}");
                return vec![];
            }
        };

        match certificate.serialize_request_der() {
            Ok(csr) => csr,
            Err(e) => {
                warn!("Could not serialize mTLS CSR, falling back to legacy renewal flow: {e}");
                vec![]
            }
        }
    }

    pub async fn refresh_certificate_async(
        &self,
        signatory: &Signatory,
        options: &CertificateConfig,
        notification_function: &Option<Box<dyn Fn() + Send + Sync>>,
        mtls_csr_renewal_period: u64,
    ) -> Result<(RusticaCert, Option<MtlsCredentials>), RefreshError> {
        let (mut client, challenge) =
            super::complete_rustica_challenge(self, signatory, notification_function).await?;

        let current_timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(ts) => ts.as_secs(),
            Err(_e) => 0xFFFFFFFFFFFFFFFF,
        };

        let request = tonic::Request::new(CertificateRequest {
            cert_type: options.cert_type as u32,
            key_id: options.authority.clone(),
            critical_options: HashMap::new(),
            extensions: Certificate::standard_extensions(),
            servers: options.hosts.clone(),
            principals: options.principals.clone(),
            valid_before: current_timestamp + options.duration,
            valid_after: current_timestamp,
            challenge: Some(challenge),
            mtls_csr: self.create_mtls_refresh_csr(mtls_csr_renewal_period),
        });

        let response = client.certificate(request).await?;
        let response = response.into_inner();

        if response.error_code != 0 {
            return Err(RefreshError::RusticaServerError(ServerError {
                code: response.error_code,
                message: response.error,
            }));
        }

        // If there is a certificate, then create a new MtlsCredentials struct
        // and return it. It's possible in the future the server will only
        // return the certificate which is why we only check the certificate.
        let mtls_credentials = if !response.new_client_certificate.is_empty() {
            Some(MtlsCredentials {
                certificate: response.new_client_certificate,
                key: response.new_client_key,
            })
        } else {
            None
        };

        Ok((
            RusticaCert {
                cert: response.certificate,
                comment: "JITC".to_string(),
            },
            mtls_credentials,
        ))
    }

    pub fn get_custom_certificate(
        &self,
        signatory: &mut Signatory,
        options: &CertificateConfig,
        handle: &Handle,
        notification_function: &Option<Box<dyn Fn() + Send + Sync>>,
        mtls_csr_renewal_period: u64,
    ) -> Result<(RusticaCert, Option<MtlsCredentials>), RefreshError> {
        handle.block_on(async {
            self.refresh_certificate_async(
                signatory,
                options,
                notification_function,
                mtls_csr_renewal_period,
            )
            .await
        })
    }
}
