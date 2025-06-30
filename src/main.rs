use actix_web::{
    web, App, HttpResponse, HttpServer, Result,
    get, post, Responder
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_sdk::{
    signer::{keypair::Keypair, Signer},
    pubkey::Pubkey,
    instruction::{AccountMeta, Instruction},
    signature::Signature,
};
use spl_token;
use std::str::FromStr;
use solana_sdk::system_instruction;
use base64::engine::general_purpose;
use base64::Engine;





#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}





#[derive(Deserialize)]
struct PostData {
    message: String,
}

#[derive(Deserialize)]
struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    mint_authority: String,
    mint: String,
    decimals: u8,
}

#[derive(Deserialize)]
struct MintTokenRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

// #[derive(Deserialize)]
// struct VerifyMessageRequest {
//     message: String,
//     signature: String,
//     pubkey: String,
// }

// #[derive(Serialize)]
// struct VerifyMessageResponse {
//     valid: bool,
//     message: String,
//     pubkey: String,
// }

#[derive(Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Serialize)]
struct AccountInfo {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct MintTokenResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}

#[derive(Serialize)]
struct SignMessageResponse {
    signature: String,
    public_key: String,
    message: String,
}



#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}







#[get("/")]
async fn get_handler() -> Result<impl Responder> {
    println!("GET request received");

    // Simulate a success response
    let response = SuccessResponse {
        success: true,
        data: json!({
            "message": "GET request logged"
        }),
    };

    Ok(HttpResponse::Ok().json(response))
}

#[post("/")]
async fn post_handler(data: web::Json<PostData>) -> Result<HttpResponse> {
    println!("POST request received: {}", data.message);
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "POST request logged"
    })))
}

#[post("/token/create")]
async fn create_token(request: web::Json<CreateTokenRequest>) -> Result<HttpResponse> {
    println!("Creating SPL token with decimals: {}", request.decimals);
    
    // Parse public keys from base58
    let mint_authority = match Pubkey::from_str(&request.mint_authority) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid mint authority public key: {}", e),
        }))
    };
    
    let mint = match Pubkey::from_str(&request.mint) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid mint public key: {}", e),
        }))
    };
    
    // Create initialize mint instruction
    let instruction = match spl_token::instruction::initialize_mint(
        &spl_token::ID,
        &mint,
        &mint_authority,
        Some(&mint_authority),
        request.decimals,
    ) {
        Ok(inst) => inst,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
            success: false,
            error: format!("Failed to create initialize mint instruction: {}", e),
        }))
    };
    
    // Convert accounts to our response format
    let accounts: Vec<AccountInfo> = instruction.accounts.iter().map(|acc| {
        AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        }
    }).collect();
    
    let response = SuccessResponse {
        success: true,
        data: CreateTokenResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        },
    };
    
    println!("Created token instruction for mint: {}", mint);
    Ok(HttpResponse::Ok().json(response))
}



#[post("/token/mint")]
async fn mint_token(request: web::Json<MintTokenRequest>) -> Result<HttpResponse> {
    println!("Minting {} tokens to destination", request.amount);
    
    // Parse public keys from base58
    let mint = match Pubkey::from_str(&request.mint) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid mint public key: {}", e),
        }))
    };
    
    let destination = match Pubkey::from_str(&request.destination) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid destination public key: {}", e),
        }))
    };
    
    let authority = match Pubkey::from_str(&request.authority) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid authority public key: {}", e),
        }))
    };
    
    // Create mint-to instruction
    let instruction = match spl_token::instruction::mint_to(
        &spl_token::ID,
        &mint,
        &destination,
        &authority,
        &[],
        request.amount,
    ) {
        Ok(inst) => inst,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
            success: false,
            error: format!("Failed to create mint-to instruction: {}", e),
        }))
    };
    
    // Convert accounts to our response format
    let accounts: Vec<AccountInfo> = instruction.accounts.iter().map(|acc| {
        AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        }
    }).collect();
    
    let response = SuccessResponse {
        success: true,
        data: MintTokenResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        },
    };
    
    println!("Created mint-to instruction for {} tokens to {}", request.amount, destination);
    Ok(HttpResponse::Ok().json(response))
}



#[post("/keypair")]
async fn generate_keypair() -> Result<HttpResponse> {
    println!("Generating new Solana keypair");
    
    // Generate keypair - this shouldn't fail, but we can still handle it gracefully
    let keypair = match std::panic::catch_unwind(|| Keypair::new()) {
        Ok(kp) => kp,
        Err(_) => return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
            success: false,
            error: "Failed to generate keypair".to_string(),
        }))
    };
    
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(&keypair.to_bytes()).into_string();
    
    let response = SuccessResponse {
        success: true,
        data: KeypairResponse {
            pubkey: pubkey.clone(),
            secret,
        },
    };
    
    println!("Generated keypair with pubkey: {}", response.data.pubkey);
    Ok(HttpResponse::Ok().json(response))
}



#[post("/message/sign")]
async fn sign_message(request: web::Json<SignMessageRequest>) -> Result<HttpResponse> {
    println!("Signing message: {}", request.message);
    
    // Validate that required fields are present
    if request.message.is_empty() || request.secret.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Missing required fields: message and secret are required".to_string(),
        }));
    }
    
    // Decode the secret key from base58
    let secret_bytes = match bs58::decode(&request.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid secret key format: {}", e),
        }))
    };
    
    // Create keypair from secret key bytes
    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid secret key: {}", e),
        }))
    };
    
    // Sign the message
    let message_bytes = request.message.as_bytes();
    let signature = keypair.sign_message(message_bytes);
    
    // Encode signature as base64 and public key as base58
    let signature_b64 = base64::encode(signature.as_ref());
    let public_key_b58 = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    
    let response = SuccessResponse {
        success: true,
        data: SignMessageResponse {
            signature: signature_b64,
            public_key: public_key_b58,
            message: request.message.clone(),
        },
    };
    
    println!("Signed message with public key: {}", response.data.public_key);
    Ok(HttpResponse::Ok().json(response))
}



#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[post("/message/verify")]
async fn verify_message(request: web::Json<VerifyMessageRequest>) -> Result<HttpResponse> {
    println!("Verifying message: {}", request.message);

   
    if request.message.is_empty() || request.signature.is_empty() || request.pubkey.is_empty() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Missing required fields"
        })));
    }

 
    let pubkey = match Pubkey::from_str(&request.pubkey) {
        Ok(pk) => pk,
        Err(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Invalid public key format"
        }))),
    };

  
    let signature_bytes = match base64::engine::general_purpose::STANDARD.decode(&request.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Invalid signature format"
        }))),
    };

  
    let signature = match solana_sdk::signature::Signature::try_from(signature_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error": "Invalid signature structure"
        }))),
    };

    
    let message_bytes = request.message.as_bytes();
    let is_valid = signature.verify(&pubkey.to_bytes(), message_bytes);

    let response = ApiResponse {
        success: true,
        data: VerifyMessageResponse {
            valid: is_valid,
            message: request.message.clone(),
            pubkey: request.pubkey.clone(),
        },
    };

    println!("Message verification result: {} for pubkey: {}", is_valid, request.pubkey);
    Ok(HttpResponse::Ok().json(response))
}




#[post("/send/token")]
async fn send_token(request: web::Json<SendTokenRequest>) -> Result<HttpResponse> {
    println!(
        "Generating SPL token transfer instruction: {} tokens from owner {} to destination {} for mint {}",
        request.amount, request.owner, request.destination, request.mint
    );

 
    let mint = match Pubkey::from_str(&request.mint) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid mint public key: {}", e),
        }))
    };
    
    let destination = match Pubkey::from_str(&request.destination) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid destination public key: {}", e),
        }))
    };
    
    let owner = match Pubkey::from_str(&request.owner) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid owner public key: {}", e),
        }))
    };

   
    let source = spl_associated_token_account::get_associated_token_address(&owner, &mint);

  
    let destination_token = spl_associated_token_account::get_associated_token_address(&destination, &mint);

 
    let instruction = match spl_token::instruction::transfer(
        &spl_token::ID,
        &source,
        &destination_token,
        &owner,
        &[],
        request.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
            success: false,
            error: format!("Failed to create token transfer instruction: {}", e),
        }))
    };

   
    let accounts: Vec<AccountInfo> = instruction.accounts.iter().map(|acc| {
        AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        }
    }).collect();

    let response = SuccessResponse {
        success: true,
        data: SendTokenResponse {
            program_id: instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&instruction.data),
        },
    };

    println!("Token transfer instruction generated");
    Ok(HttpResponse::Ok().json(response))
}



#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<AccountInfo>,
    instruction_data: String,
}


#[post("/send/sol")]
async fn send_sol(request: web::Json<SendSolRequest>) -> Result<HttpResponse> {
    println!(
        "Creating SOL transfer: {} lamports from {} to {}",
        request.lamports, request.from, request.to
    );

 
    if request.lamports == 0 {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Lamports amount must be greater than 0".to_string(),
        }));
    }

    // Parse and validate 'from' address
    let from_pubkey = match Pubkey::from_str(&request.from) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid 'from' address: {}", e),
        }))
    };

    // Parse and validate 'to' address
    let to_pubkey = match Pubkey::from_str(&request.to) {
        Ok(pk) => pk,
        Err(e) => return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: format!("Invalid 'to' address: {}", e),
        }))
    };

    // Validate that from and to addresses are different
    if from_pubkey == to_pubkey {
        return Ok(HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Cannot transfer to the same address".to_string(),
        }));
    }

    // Create the transfer instruction
    let transfer_instruction = system_instruction::transfer(
        &from_pubkey,
        &to_pubkey,
        request.lamports,
    );

    // Convert accounts to our response format
    let accounts: Vec<AccountInfo> = transfer_instruction.accounts.iter().map(|acc| {
        AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        }
    }).collect();

    let response = SuccessResponse {
        success: true,
        data: SendSolResponse {
            program_id: transfer_instruction.program_id.to_string(),
            accounts,
            instruction_data: base64::encode(&transfer_instruction.data),
        },
    };

    println!("SOL transfer instruction created successfully");
    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("🚀 Server running on http://localhost:8080");
    
    HttpServer::new(|| {
        App::new()
            .service(get_handler)
            .service(post_handler)
            .service(generate_keypair)
            .service(create_token)
            .service(mint_token)
            .service(sign_message)
            .service(send_token)
            .service(send_sol)
            .service(verify_message)
        
        // .service(verify_message) 
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}