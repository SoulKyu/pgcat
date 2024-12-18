use crate::config::AuthType;
use crate::errors::Error;
use crate::pool::ConnectionPool;
use crate::server::Server;
use log::debug;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use pbkdf2::pbkdf2_hmac;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use subtle::ConstantTimeEq;
use md5::Md5;

#[derive(Clone, Debug)]
pub struct AuthPassthrough {
    password: String,
    query: String,
    user: String,
}

impl AuthPassthrough {
    /// Initializes an AuthPassthrough.
    pub fn new(query: &str, user: &str, password: &str) -> Self {
        AuthPassthrough {
            password: password.to_string(),
            query: query.to_string(),
            user: user.to_string(),
        }
    }

    /// Returns an AuthPassthrough given the pool configuration.
    /// If any of required values is not set, None is returned.
    pub fn from_pool_config(pool_config: &crate::config::Pool) -> Option<Self> {
        if pool_config.is_auth_query_configured() {
            return Some(AuthPassthrough::new(
                pool_config.auth_query.as_ref().unwrap(),
                pool_config.auth_query_user.as_ref().unwrap(),
                pool_config.auth_query_password.as_ref().unwrap(),
            ));
        }

        None
    }

    /// Returns an AuthPassthrough given the pool settings.
    /// If any of required values is not set, None is returned.
    pub fn from_pool_settings(pool_settings: &crate::pool::PoolSettings) -> Option<Self> {
        let pool_config = crate::config::Pool {
            auth_query: pool_settings.auth_query.clone(),
            auth_query_password: pool_settings.auth_query_password.clone(),
            auth_query_user: pool_settings.auth_query_user.clone(),
            ..Default::default()
        };

        AuthPassthrough::from_pool_config(&pool_config)
    }

    /// Connects to server and executes auth_query for the specified address.
    /// If the response is a row with two columns containing the username set in the address.
    /// and its MD5 hash, the MD5 hash returned.
    ///
    /// Note that the query is executed, changing $1 with the name of the user
    /// this is so we only hold in memory (and transfer) the least amount of 'sensitive' data.
    /// Also, it is compatible with pgbouncer.
    ///
    /// # Arguments
    ///
    /// * `address` - An Address of the server we want to connect to. The username for the hash will be obtained from this value.
    ///
    /// # Examples
    ///
    /// ```
    /// use pgcat::auth_passthrough::AuthPassthrough;
    /// use pgcat::config::Address;
    /// let auth_passthrough = AuthPassthrough::new("SELECT * FROM public.user_lookup('$1');", "postgres", "postgres");
    /// auth_passthrough.fetch_hash(&Address::default());
    /// ```
    ///
    pub async fn fetch_hash(&self, address: &crate::config::Address) -> Result<String, Error> {
        let auth_user = crate::config::User {
            username: self.user.clone(),
            auth_type: AuthType::MD5,
            password: Some(self.password.clone()),
            server_username: None,
            server_password: None,
            pool_size: 1,
            statement_timeout: 0,
            pool_mode: None,
            server_lifetime: None,
            min_pool_size: None,
            connect_timeout: None,
            idle_timeout: None,
        };
    
        let user = &address.username;
    
        debug!("Connecting to server to obtain auth hashes");
    
        let auth_query = self.query.replace("$1", user);
    
        match Server::exec_simple_query(address, &auth_user, &auth_query).await {
            Ok(password_data) => {
                if password_data.len() == 2 && password_data.first().unwrap() == user {
                    // Get the hash value
                    let hash = password_data.last().unwrap().to_string();
                    
                    // Check if it's either MD5 or SCRAM-SHA-256
                    if hash.starts_with("md5") || hash.starts_with("SCRAM-SHA-256") {
                        Ok(hash)
                    } else {
                        Err(Error::AuthPassthroughError(
                            "Obtained hash is neither MD5 nor SCRAM-SHA-256 format.".to_string(),
                        ))
                    }
                } else {
                    Err(Error::AuthPassthroughError(
                        "Data obtained from query does not follow the scheme 'user','hash'."
                            .to_string(),
                    ))
                 }
            }
            Err(err) => {
                Err(Error::AuthPassthroughError(
                    format!("Error trying to obtain password from auth_query, ignoring hash for user '{}'. Error: {:?}",
                        user, err))
                )
            }
        }
    }
}

impl AuthPassthrough {
    pub async fn verify_password(&self, password: &str, hash: &str) -> Result<bool, Error> {
        if hash.starts_with("SCRAM-SHA-256") {
            self.verify_scram_password(password, hash)
        } else if hash.starts_with("md5") {
            self.verify_md5_password(password, hash)
        } else {
            Err(Error::AuthPassthroughError(
                "Unsupported password hash format".to_string(),
            ))
        }
    }

    fn verify_scram_password(&self, password: &str, hash: &str) -> Result<bool, Error> {
        let parts = parse_scram_sha256(hash)?;
        
        // 1. Derive the client key
        let salt = STANDARD.decode(&parts.salt)
            .map_err(|_| Error::AuthPassthroughError("Invalid salt".to_string()))?;
        
        let salted_password = pbkdf2_hmac_sha256(
            password.as_bytes(),
            &salt,
            parts.iteration_count,
            32,
        );
        
        // Client key verification
        let client_key = hmac_sha256("Client Key".as_bytes(), &salted_password);
        let stored_key = sha256(&client_key);
        
        // Server key verification
        let server_key = hmac_sha256("Server Key".as_bytes(), &salted_password);
        
        // 2. Compare both stored key and server key
        let expected_stored_key = STANDARD.decode(&parts.stored_key)
            .map_err(|_| Error::AuthPassthroughError("Invalid stored key".to_string()))?;
            
        let expected_server_key = STANDARD.decode(&parts.server_key)
            .map_err(|_| Error::AuthPassthroughError("Invalid server key".to_string()))?;
        
        Ok(constant_time_eq(&stored_key, &expected_stored_key) &&
           constant_time_eq(&server_key, &expected_server_key))
    }

    fn verify_md5_password(&self, password: &str, hash: &str) -> Result<bool, Error> {
        if !hash.starts_with("md5") {
            return Err(Error::AuthPassthroughError(
                "Invalid MD5 hash format".to_string(),
            ));
        }
        
        let mut hasher = Md5::new();
        hasher.update(password.as_bytes());
        let password_hash = format!("md5{:x}", hasher.finalize());
        
        Ok(constant_time_eq(
            password_hash.as_bytes(),
            hash.as_bytes()
        ))
    }
}

#[derive(Debug)]
struct ScramSha256Parts {
    iteration_count: u32,
    salt: String,
    stored_key: String,
    server_key: String,
}

fn parse_scram_sha256(hash: &str) -> Result<ScramSha256Parts, Error> {
    let parts: Vec<&str> = hash.split('$').collect();
    if parts.len() != 3 {
        return Err(Error::AuthPassthroughError(
            "Invalid SCRAM-SHA-256 hash format".to_string(),
        ));
    }

    let iteration_count = parts[1]
        .split(':')
        .next()
        .ok_or_else(|| Error::AuthPassthroughError("Missing iteration count".to_string()))?
        .parse::<u32>()
        .map_err(|_| Error::AuthPassthroughError("Invalid iteration count".to_string()))?;

    let salt = parts[1]
        .split(':')
        .nth(1)
        .ok_or_else(|| Error::AuthPassthroughError("Missing salt".to_string()))?
        .to_string();

    let key_parts: Vec<&str> = parts[2].split(':').collect();
    if key_parts.len() != 2 {
        return Err(Error::AuthPassthroughError(
            "Invalid stored/server key format".to_string(),
        ));
    }

    Ok(ScramSha256Parts {
        iteration_count,
        salt,
        stored_key: key_parts[0].to_string(),
        server_key: key_parts[1].to_string(),
    })
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, output_len: usize) -> Vec<u8> {
    let mut result = vec![0u8; output_len];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut result);
    result
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

pub async fn refetch_auth_hash(pool: &ConnectionPool) -> Result<String, Error> {
    let address = pool.address(0, 0);
    if let Some(apt) = AuthPassthrough::from_pool_settings(&pool.settings) {
        let hash = apt.fetch_hash(address).await?;

        return Ok(hash);
    }

    Err(Error::ClientError(format!(
        "Could not obtain hash for {{ username: {:?}, database: {:?} }}. Auth passthrough not enabled.",
        address.username, address.database
    )))
}
