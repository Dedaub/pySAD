abi = [
    {
        "name": "AllowanceExpired",
        "type": "error",
        "inputs": [{"name": "deadline", "type": "uint256", "internalType": "uint256"}],
    },
    {"name": "ExcessiveInvalidation", "type": "error", "inputs": []},
    {
        "name": "InsufficientAllowance",
        "type": "error",
        "inputs": [{"name": "amount", "type": "uint256", "internalType": "uint256"}],
    },
    {
        "name": "InvalidAmount",
        "type": "error",
        "inputs": [{"name": "maxAmount", "type": "uint256", "internalType": "uint256"}],
    },
    {"name": "InvalidContractSignature", "type": "error", "inputs": []},
    {"name": "InvalidNonce", "type": "error", "inputs": []},
    {"name": "InvalidSignature", "type": "error", "inputs": []},
    {"name": "InvalidSignatureLength", "type": "error", "inputs": []},
    {"name": "InvalidSigner", "type": "error", "inputs": []},
    {"name": "LengthMismatch", "type": "error", "inputs": []},
    {
        "name": "SignatureExpired",
        "type": "error",
        "inputs": [
            {"name": "signatureDeadline", "type": "uint256", "internalType": "uint256"}
        ],
    },
    {
        "name": "Approval",
        "type": "event",
        "inputs": [
            {
                "name": "owner",
                "type": "address",
                "indexed": True,
                "internalType": "address",
            },
            {
                "name": "token",
                "type": "address",
                "indexed": True,
                "internalType": "address",
            },
            {
                "name": "spender",
                "type": "address",
                "indexed": True,
                "internalType": "address",
            },
            {
                "name": "amount",
                "type": "uint160",
                "indexed": False,
                "internalType": "uint160",
            },
            {
                "name": "expiration",
                "type": "uint48",
                "indexed": False,
                "internalType": "uint48",
            },
        ],
        "anonymous": False,
    },
    {
        "name": "Lockdown",
        "type": "event",
        "inputs": [
            {
                "name": "owner",
                "type": "address",
                "indexed": True,
                "internalType": "address",
            },
            {
                "name": "token",
                "type": "address",
                "indexed": False,
                "internalType": "address",
            },
            {
                "name": "spender",
                "type": "address",
                "indexed": False,
                "internalType": "address",
            },
        ],
        "anonymous": False,
    },
    {
        "name": "NonceInvalidation",
        "type": "event",
        "inputs": [
            {
                "name": "owner",
                "type": "address",
                "indexed": True,
                "internalType": "address",
            },
            {
                "name": "token",
                "type": "address",
                "indexed": True,
                "internalType": "address",
            },
            {
                "name": "spender",
                "type": "address",
                "indexed": True,
                "internalType": "address",
            },
            {
                "name": "newNonce",
                "type": "uint48",
                "indexed": False,
                "internalType": "uint48",
            },
            {
                "name": "oldNonce",
                "type": "uint48",
                "indexed": False,
                "internalType": "uint48",
            },
        ],
        "anonymous": False,
    },
    {
        "name": "Permit",
        "type": "event",
        "inputs": [
            {
                "name": "owner",
                "type": "address",
                "indexed": True,
                "internalType": "address",
            },
            {
                "name": "token",
                "type": "address",
                "indexed": True,
                "internalType": "address",
            },
            {
                "name": "spender",
                "type": "address",
                "indexed": True,
                "internalType": "address",
            },
            {
                "name": "amount",
                "type": "uint160",
                "indexed": False,
                "internalType": "uint160",
            },
            {
                "name": "expiration",
                "type": "uint48",
                "indexed": False,
                "internalType": "uint48",
            },
            {
                "name": "nonce",
                "type": "uint48",
                "indexed": False,
                "internalType": "uint48",
            },
        ],
        "anonymous": False,
    },
    {
        "name": "UnorderedNonceInvalidation",
        "type": "event",
        "inputs": [
            {
                "name": "owner",
                "type": "address",
                "indexed": True,
                "internalType": "address",
            },
            {
                "name": "word",
                "type": "uint256",
                "indexed": False,
                "internalType": "uint256",
            },
            {
                "name": "mask",
                "type": "uint256",
                "indexed": False,
                "internalType": "uint256",
            },
        ],
        "anonymous": False,
    },
    {
        "name": "DOMAIN_SEPARATOR",
        "type": "function",
        "inputs": [],
        "outputs": [{"name": "", "type": "bytes32", "internalType": "bytes32"}],
        "stateMutability": "view",
    },
    {
        "name": "allowance",
        "type": "function",
        "inputs": [
            {"name": "", "type": "address", "internalType": "address"},
            {"name": "", "type": "address", "internalType": "address"},
            {"name": "", "type": "address", "internalType": "address"},
        ],
        "outputs": [
            {"name": "amount", "type": "uint160", "internalType": "uint160"},
            {"name": "expiration", "type": "uint48", "internalType": "uint48"},
            {"name": "nonce", "type": "uint48", "internalType": "uint48"},
        ],
        "stateMutability": "view",
    },
    {
        "name": "approve",
        "type": "function",
        "inputs": [
            {"name": "token", "type": "address", "internalType": "address"},
            {"name": "spender", "type": "address", "internalType": "address"},
            {"name": "amount", "type": "uint160", "internalType": "uint160"},
            {"name": "expiration", "type": "uint48", "internalType": "uint48"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "invalidateNonces",
        "type": "function",
        "inputs": [
            {"name": "token", "type": "address", "internalType": "address"},
            {"name": "spender", "type": "address", "internalType": "address"},
            {"name": "newNonce", "type": "uint48", "internalType": "uint48"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "invalidateUnorderedNonces",
        "type": "function",
        "inputs": [
            {"name": "wordPos", "type": "uint256", "internalType": "uint256"},
            {"name": "mask", "type": "uint256", "internalType": "uint256"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "lockdown",
        "type": "function",
        "inputs": [
            {
                "name": "approvals",
                "type": "tuple[]",
                "components": [
                    {"name": "token", "type": "address", "internalType": "address"},
                    {"name": "spender", "type": "address", "internalType": "address"},
                ],
                "internalType": "struct IAllowanceTransfer.TokenSpenderPair[]",
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "nonceBitmap",
        "type": "function",
        "inputs": [
            {"name": "", "type": "address", "internalType": "address"},
            {"name": "", "type": "uint256", "internalType": "uint256"},
        ],
        "outputs": [{"name": "", "type": "uint256", "internalType": "uint256"}],
        "stateMutability": "view",
    },
    {
        "name": "permit",
        "type": "function",
        "inputs": [
            {"name": "owner", "type": "address", "internalType": "address"},
            {
                "name": "permitBatch",
                "type": "tuple",
                "components": [
                    {
                        "name": "details",
                        "type": "tuple[]",
                        "components": [
                            {
                                "name": "token",
                                "type": "address",
                                "internalType": "address",
                            },
                            {
                                "name": "amount",
                                "type": "uint160",
                                "internalType": "uint160",
                            },
                            {
                                "name": "expiration",
                                "type": "uint48",
                                "internalType": "uint48",
                            },
                            {
                                "name": "nonce",
                                "type": "uint48",
                                "internalType": "uint48",
                            },
                        ],
                        "internalType": "struct IAllowanceTransfer.PermitDetails[]",
                    },
                    {"name": "spender", "type": "address", "internalType": "address"},
                    {
                        "name": "sigDeadline",
                        "type": "uint256",
                        "internalType": "uint256",
                    },
                ],
                "internalType": "struct IAllowanceTransfer.PermitBatch",
            },
            {"name": "signature", "type": "bytes", "internalType": "bytes"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "permit",
        "type": "function",
        "inputs": [
            {"name": "owner", "type": "address", "internalType": "address"},
            {
                "name": "permitSingle",
                "type": "tuple",
                "components": [
                    {
                        "name": "details",
                        "type": "tuple",
                        "components": [
                            {
                                "name": "token",
                                "type": "address",
                                "internalType": "address",
                            },
                            {
                                "name": "amount",
                                "type": "uint160",
                                "internalType": "uint160",
                            },
                            {
                                "name": "expiration",
                                "type": "uint48",
                                "internalType": "uint48",
                            },
                            {
                                "name": "nonce",
                                "type": "uint48",
                                "internalType": "uint48",
                            },
                        ],
                        "internalType": "struct IAllowanceTransfer.PermitDetails",
                    },
                    {"name": "spender", "type": "address", "internalType": "address"},
                    {
                        "name": "sigDeadline",
                        "type": "uint256",
                        "internalType": "uint256",
                    },
                ],
                "internalType": "struct IAllowanceTransfer.PermitSingle",
            },
            {"name": "signature", "type": "bytes", "internalType": "bytes"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "permitTransferFrom",
        "type": "function",
        "inputs": [
            {
                "name": "permit",
                "type": "tuple",
                "components": [
                    {
                        "name": "permitted",
                        "type": "tuple",
                        "components": [
                            {
                                "name": "token",
                                "type": "address",
                                "internalType": "address",
                            },
                            {
                                "name": "amount",
                                "type": "uint256",
                                "internalType": "uint256",
                            },
                        ],
                        "internalType": "struct ISignatureTransfer.TokenPermissions",
                    },
                    {"name": "nonce", "type": "uint256", "internalType": "uint256"},
                    {"name": "deadline", "type": "uint256", "internalType": "uint256"},
                ],
                "internalType": "struct ISignatureTransfer.PermitTransferFrom",
            },
            {
                "name": "transferDetails",
                "type": "tuple",
                "components": [
                    {"name": "to", "type": "address", "internalType": "address"},
                    {
                        "name": "requestedAmount",
                        "type": "uint256",
                        "internalType": "uint256",
                    },
                ],
                "internalType": "struct ISignatureTransfer.SignatureTransferDetails",
            },
            {"name": "owner", "type": "address", "internalType": "address"},
            {"name": "signature", "type": "bytes", "internalType": "bytes"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "permitTransferFrom",
        "type": "function",
        "inputs": [
            {
                "name": "permit",
                "type": "tuple",
                "components": [
                    {
                        "name": "permitted",
                        "type": "tuple[]",
                        "components": [
                            {
                                "name": "token",
                                "type": "address",
                                "internalType": "address",
                            },
                            {
                                "name": "amount",
                                "type": "uint256",
                                "internalType": "uint256",
                            },
                        ],
                        "internalType": "struct ISignatureTransfer.TokenPermissions[]",
                    },
                    {"name": "nonce", "type": "uint256", "internalType": "uint256"},
                    {"name": "deadline", "type": "uint256", "internalType": "uint256"},
                ],
                "internalType": "struct ISignatureTransfer.PermitBatchTransferFrom",
            },
            {
                "name": "transferDetails",
                "type": "tuple[]",
                "components": [
                    {"name": "to", "type": "address", "internalType": "address"},
                    {
                        "name": "requestedAmount",
                        "type": "uint256",
                        "internalType": "uint256",
                    },
                ],
                "internalType": "struct ISignatureTransfer.SignatureTransferDetails[]",
            },
            {"name": "owner", "type": "address", "internalType": "address"},
            {"name": "signature", "type": "bytes", "internalType": "bytes"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "permitWitnessTransferFrom",
        "type": "function",
        "inputs": [
            {
                "name": "permit",
                "type": "tuple",
                "components": [
                    {
                        "name": "permitted",
                        "type": "tuple",
                        "components": [
                            {
                                "name": "token",
                                "type": "address",
                                "internalType": "address",
                            },
                            {
                                "name": "amount",
                                "type": "uint256",
                                "internalType": "uint256",
                            },
                        ],
                        "internalType": "struct ISignatureTransfer.TokenPermissions",
                    },
                    {"name": "nonce", "type": "uint256", "internalType": "uint256"},
                    {"name": "deadline", "type": "uint256", "internalType": "uint256"},
                ],
                "internalType": "struct ISignatureTransfer.PermitTransferFrom",
            },
            {
                "name": "transferDetails",
                "type": "tuple",
                "components": [
                    {"name": "to", "type": "address", "internalType": "address"},
                    {
                        "name": "requestedAmount",
                        "type": "uint256",
                        "internalType": "uint256",
                    },
                ],
                "internalType": "struct ISignatureTransfer.SignatureTransferDetails",
            },
            {"name": "owner", "type": "address", "internalType": "address"},
            {"name": "witness", "type": "bytes32", "internalType": "bytes32"},
            {"name": "witnessTypeString", "type": "string", "internalType": "string"},
            {"name": "signature", "type": "bytes", "internalType": "bytes"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "permitWitnessTransferFrom",
        "type": "function",
        "inputs": [
            {
                "name": "permit",
                "type": "tuple",
                "components": [
                    {
                        "name": "permitted",
                        "type": "tuple[]",
                        "components": [
                            {
                                "name": "token",
                                "type": "address",
                                "internalType": "address",
                            },
                            {
                                "name": "amount",
                                "type": "uint256",
                                "internalType": "uint256",
                            },
                        ],
                        "internalType": "struct ISignatureTransfer.TokenPermissions[]",
                    },
                    {"name": "nonce", "type": "uint256", "internalType": "uint256"},
                    {"name": "deadline", "type": "uint256", "internalType": "uint256"},
                ],
                "internalType": "struct ISignatureTransfer.PermitBatchTransferFrom",
            },
            {
                "name": "transferDetails",
                "type": "tuple[]",
                "components": [
                    {"name": "to", "type": "address", "internalType": "address"},
                    {
                        "name": "requestedAmount",
                        "type": "uint256",
                        "internalType": "uint256",
                    },
                ],
                "internalType": "struct ISignatureTransfer.SignatureTransferDetails[]",
            },
            {"name": "owner", "type": "address", "internalType": "address"},
            {"name": "witness", "type": "bytes32", "internalType": "bytes32"},
            {"name": "witnessTypeString", "type": "string", "internalType": "string"},
            {"name": "signature", "type": "bytes", "internalType": "bytes"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "transferFrom",
        "type": "function",
        "inputs": [
            {
                "name": "transferDetails",
                "type": "tuple[]",
                "components": [
                    {"name": "from", "type": "address", "internalType": "address"},
                    {"name": "to", "type": "address", "internalType": "address"},
                    {"name": "amount", "type": "uint160", "internalType": "uint160"},
                    {"name": "token", "type": "address", "internalType": "address"},
                ],
                "internalType": "struct IAllowanceTransfer.AllowanceTransferDetails[]",
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "name": "transferFrom",
        "type": "function",
        "inputs": [
            {"name": "from", "type": "address", "internalType": "address"},
            {"name": "to", "type": "address", "internalType": "address"},
            {"name": "amount", "type": "uint160", "internalType": "uint160"},
            {"name": "token", "type": "address", "internalType": "address"},
        ],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
]
