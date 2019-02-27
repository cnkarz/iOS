//
//  EncryptionModel.swift
//
//  Created by Cenk Arioz on 28.01.2019.
//  Copyright © 2019 Cenk Arioz. All rights reserved.
//  Ready-to-use cryptograpy code with AES-CBC

import Foundation
import CryptoSwift

class EncryptionModel {

    func encrypt(data: Data, key: String) -> Data {
        return crypt(data: data, key: key, operation: kCCEncrypt)
    }
    
    func decrypt(data: Data, key: String) -> Data {
        return crypt(data: data, key: key, operation: kCCDecrypt)
    }
    
    private func crypt(data: Data, key: String, operation: Int) -> Data {

        guard key.count == kCCKeySizeAES128 else {
            fatalError("Key size failed!")
        }
        var ivBytes: [UInt8]
        var inBytes: [UInt8]
        var outLength: Int
        
        if operation == kCCEncrypt {
            ivBytes = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
            guard kCCSuccess == SecRandomCopyBytes(kSecRandomDefault, ivBytes.count, &ivBytes) else {
                fatalError("IV creation failed!")
            }
            inBytes = Array(data)
            
        } else {
            ivBytes = Array(Array(data).dropLast(data.count - kCCBlockSizeAES128))
            inBytes = Array(Array(data).dropFirst(kCCBlockSizeAES128))
            
        }
 
        var outData: Data? = nil
        // CRYPTOSWIFT
        if operation == kCCEncrypt {
            do {
                let aes = try AES(key: key.bytes, blockMode: CBC(iv: ivBytes))
                let encrypted = try aes.encrypt(inBytes)
                let outDataCS = Data(bytes: encrypted)
                ivBytes.append(contentsOf: Array(outDataCS))
                
                outData = Data(bytes: ivBytes)
            } catch {
                print("Cryptoswift error: \(error)")
            }
        } else {
            do {
                let aes = try AES(key: key.bytes, blockMode: CBC(iv: ivBytes))
                let decrypted = try aes.decrypt(data.bytes)
                let outData = Data(bytes: decrypted)

            } catch {
                print("Cryptoswift error: \(error)")
            }
        }
        return outData!
        
    }
}
