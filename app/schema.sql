CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('officer','investigator','admin') NOT NULL,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until BIGINT NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS user_keys (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  key_algo VARCHAR(16) NOT NULL,
  public_key_pem TEXT NOT NULL,
  fingerprint CHAR(64) NOT NULL,
  created_at BIGINT NOT NULL,
  revoked_at BIGINT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id),
  UNIQUE KEY uq_fp (fingerprint),
  KEY idx_user_active (user_id, revoked_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS sessions (
  token_hash CHAR(64) PRIMARY KEY,
  user_id INT NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS transfers (
  id CHAR(32) PRIMARY KEY,
  seq BIGINT NOT NULL AUTO_INCREMENT,
  sender_id INT NOT NULL,
  recipient_id INT NOT NULL,
  sender_key_id INT NOT NULL,
  recipient_key_id INT NOT NULL,
  filename VARCHAR(255) NOT NULL,
  mime_type VARCHAR(100) NOT NULL,
  category VARCHAR(16) NOT NULL,
  size_bytes BIGINT NOT NULL,
  ciphertext_path VARCHAR(255) NOT NULL,
  ciphertext_sha256 CHAR(64) NOT NULL,
  wrapped_key VARBINARY(1024) NOT NULL,
  signature VARBINARY(1024) NOT NULL,
  signed_at BIGINT NOT NULL,
  nonce CHAR(32) NOT NULL,
  created_at BIGINT NOT NULL,
  downloaded_at BIGINT NULL,
  FOREIGN KEY (sender_id) REFERENCES users(id),
  FOREIGN KEY (recipient_id) REFERENCES users(id),
  FOREIGN KEY (sender_key_id) REFERENCES user_keys(id),
  FOREIGN KEY (recipient_key_id) REFERENCES user_keys(id),
  UNIQUE KEY uq_seq (seq),
  UNIQUE KEY uq_replay (sender_id, nonce),
  KEY idx_recipient (recipient_id, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  ts VARCHAR(32) NOT NULL,
  actor VARCHAR(64) NOT NULL,
  action VARCHAR(48) NOT NULL,
  target VARCHAR(64) NOT NULL,
  detail VARCHAR(500) NOT NULL,
  ip VARCHAR(64) NOT NULL,
  prev_hash CHAR(64) NOT NULL,
  entry_hash CHAR(64) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS metrics (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  transfer_id CHAR(32) NOT NULL,
  user_id INT NOT NULL,
  kind ENUM('send','receive','server') NOT NULL,
  plaintext_bytes BIGINT NOT NULL DEFAULT 0,
  ciphertext_bytes BIGINT NOT NULL DEFAULT 0,
  encrypt_ms DOUBLE NULL,
  decrypt_ms DOUBLE NULL,
  aes_ms DOUBLE NULL,
  mac_ms DOUBLE NULL,
  hash_ms DOUBLE NULL,
  wrap_ms DOUBLE NULL,
  unwrap_ms DOUBLE NULL,
  sign_ms DOUBLE NULL,
  verify_ms DOUBLE NULL,
  total_ms DOUBLE NULL,
  transfer_ms DOUBLE NULL,
  created_at BIGINT NOT NULL,
  FOREIGN KEY (transfer_id) REFERENCES transfers(id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  KEY idx_metrics_user (user_id, id),
  KEY idx_metrics_transfer (transfer_id, kind)
) ENGINE=InnoDB;
