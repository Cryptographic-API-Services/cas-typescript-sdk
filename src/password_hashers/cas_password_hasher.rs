pub trait CASPasswordHasher {
    fn hash_password(password_to_hash: String) -> String;
    fn verify_password(hashed_password: String, password_to_verify: String) -> bool;
}