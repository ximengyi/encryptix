use rsa::{RsaPublicKey, RsaPrivateKey, PaddingScheme};
use rand::rngs::OsRng;
use std::fs::{File};
use std::io::{Write, Read};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use clap::{Command, Arg, ArgAction};

fn encrypt_file(pub_key: &RsaPublicKey, file_path: &Path) -> std::io::Result<()> {
    let mut file = File::open(file_path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    // 使用 RSA 公钥进行加密
    let encrypted_data = pub_key.encrypt(&mut OsRng, PaddingScheme::new_pkcs1v15(), &content)
        .expect("加密失败");

    // 保存加密后的内容为新文件
    let encrypted_file_path = file_path.with_extension("enc");
    let mut encrypted_file = File::create(encrypted_file_path)?;
    encrypted_file.write_all(&encrypted_data)?;

    Ok(())
}

fn decrypt_file(priv_key: &RsaPrivateKey, file_path: &Path) -> std::io::Result<()> {
    let mut file = File::open(file_path)?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;

    // 使用 RSA 私钥进行解密
    let decrypted_data = priv_key.decrypt(PaddingScheme::new_pkcs1v15(), &encrypted_data)
        .expect("解密失败");

    // 保存解密后的内容为新文件（去掉 .enc 后缀）
    let decrypted_file_path = file_path.with_extension("");
    let mut decrypted_file = File::create(decrypted_file_path)?;
    decrypted_file.write_all(&decrypted_data)?;

    Ok(())
}

fn process_directory<F>(path: &Path, process_fn: F) -> std::io::Result<()>
where
    F: Fn(&Path) -> std::io::Result<()>,
{
    for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
        if entry.metadata()?.is_file() {
            process_fn(&entry.path())?;
        }
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    // 使用 clap 4.x 解析命令行参数
    let matches = Command::new("Encryptix")
        .version("1.0")
        .author("ximick")
        .about("一个用于加密和解密文件的工具")
        .arg(Arg::new("encrypt")
            .short('e')
            .long("encrypt")
            .action(ArgAction::SetTrue)
            .help("加密操作"))
        .arg(Arg::new("decrypt")
            .short('d')
            .long("decrypt")
            .action(ArgAction::SetTrue)
            .help("解密操作"))
        .arg(Arg::new("key")
            .short('k')
            .long("key")
            .action(ArgAction::Set)
            .required(true)
            .help("公钥或私钥文件路径"))
        .arg(Arg::new("input")
            .short('i')
            .long("input")
            .action(ArgAction::Set)
            .required(true)
            .help("输入文件或目录路径"))
        .get_matches();

    // 获取命令行参数
    let key_path = matches.get_one::<String>("key").unwrap();
    let input_path = matches.get_one::<String>("input").unwrap();
    let is_encrypt = matches.contains_id("encrypt");
    let is_decrypt = matches.contains_id("decrypt");

    // 确保只执行加密或解密其中之一
    if is_encrypt == is_decrypt {
        eprintln!("错误: 请指定只执行加密或解密操作");
        std::process::exit(1);
    }

    // 读取公钥或私钥 (假设它们是 PEM 格式)
    let key_pem = std::fs::read_to_string(key_path).expect("读取密钥文件失败");

    let pub_key = RsaPublicKey::from_public_key_pem(&key_pem).ok();
    let priv_key = RsaPrivateKey::from_private_key_pem(&key_pem).ok();

    // 确保公钥或私钥文件有效
    if pub_key.is_none() && priv_key.is_none() {
        eprintln!("错误: 无效的公钥或私钥文件");
        std::process::exit(1);
    }

    // 选择加密或解密操作
    if is_encrypt {
        if let Some(pub_key) = pub_key {
            let input_path = Path::new(input_path);
            if input_path.is_file() {
                encrypt_file(&pub_key, input_path)?;
            } else if input_path.is_dir() {
                process_directory(input_path, |file| encrypt_file(&pub_key, file))?;
            } else {
                eprintln!("无效的路径：请提供文件或目录路径");
            }
        }
    } else if is_decrypt {
        if let Some(priv_key) = priv_key {
            let input_path = Path::new(input_path);
            if input_path.is_file() {
                decrypt_file(&priv_key, input_path)?;
            } else if input_path.is_dir() {
                process_directory(input_path, |file| decrypt_file(&priv_key, file))?;
            } else {
                eprintln!("无效的路径：请提供文件或目录路径");
            }
        }
    }

    println!("操作完成！");
    Ok(())
}
