//
//  EncryptionModel.swift
//
//  Created by Cenk Arioz on 28.01.2019.
//  Copyright © 2019 Cenk Arioz. All rights reserved.
//  Ready-to-use cryptograpy code with AES-CBC

import Foundation
import CryptoSwift

class EncryptionModel {

    enum Operation {
        case encrypt
        case decrypt
    }
    
    private let keySizeAES128 = 16
    private let aesBlockSize = 16
    
    func encrypt(data: Data, key: String) -> Data {
        return crypt(data: data, key: key, operation: .encrypt)
    }
    
    func decrypt(data: Data, key: String) -> Data {
        return crypt(data: data, key: key, operation: .decrypt)
    }
    
    private func crypt(data: Data, key: String, operation: Operation) -> Data {
        
        guard key.count == keySizeAES128 else {
            fatalError("Key size failed!")
        }
        var outData: Data? = nil
        
        if operation == .encrypt {
            var ivBytes = [UInt8](repeating: 0, count: aesBlockSize)
            guard 0 == SecRandomCopyBytes(kSecRandomDefault, ivBytes.count, &ivBytes) else {
                fatalError("IV creation failed!")
            }
            
            do {
                let aes = try AES(key: Array(key.data(using: .utf8)!), blockMode: CBC(iv: ivBytes))
                let encrypted = try aes.encrypt(Array(data))
                ivBytes.append(contentsOf: encrypted)
                outData = Data(bytes: ivBytes)
                
            } catch {
                print("Encryption error: \(error)")
            }
            
        } else {
            let ivBytes = Array(Array(data).dropLast(data.count - aesBlockSize))
            let inBytes = Array(Array(data).dropFirst(aesBlockSize))

            do {
                let aes = try AES(key: Array(key.data(using: .utf8)!), blockMode: CBC(iv: ivBytes))
                let decrypted = try aes.decrypt(inBytes)
                outData = Data(bytes: decrypted)
                
            } catch {
                print("Decryption error: \(error)")
            }
        }
        return outData!

    }
}
