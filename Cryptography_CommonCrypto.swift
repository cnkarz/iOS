//
//  EncryptionModel.swift
//
//  Created by Cenk Arioz on 28.01.2019.
//  Copyright © 2019 Cenk Arioz. All rights reserved.
//  Ready-to-use cryptograpy code with AES-CBC

import Foundation
import CommonCrypto

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
            outLength = data.count + kCCBlockSizeAES128
            
        } else {
            ivBytes = Array(Array(data).dropLast(data.count - kCCBlockSizeAES128))
            inBytes = Array(Array(data).dropFirst(kCCBlockSizeAES128))
            outLength = inBytes.count
            
        }
        var outBytes = [UInt8](repeating: 0, count: outLength)
        var bytesMutated = 0
        
        guard kCCSuccess == CCCrypt(CCOperation(operation), CCAlgorithm(kCCAlgorithmAES128), CCOptions(kCCOptionPKCS7Padding), Array(key), kCCKeySizeAES128, &ivBytes, &inBytes, inBytes.count, &outBytes, outLength, &bytesMutated) else {
            fatalError("Cryptography operation \(operation) failed")
        }
        
        var outData = Data(bytes: &outBytes, count: bytesMutated)
        
        if operation == kCCEncrypt {
            ivBytes.append(contentsOf: Array(outData))
            outData = Data(bytes: ivBytes)
        }
        return outData
        
    }
}
