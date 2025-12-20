import CryptoJS from 'crypto-js';

// Helper for safe execution
const safeOp = (fn, input, ...args) => {
    try {
        return fn(input, ...args);
    } catch (e) {
        return 'Error: ' + e.message;
    }
};

export const categories = {
    'Data format': [
        {
            name: 'To Base64',
            description: 'Encode text to Base64',
            run: (input) => safeOp(btoa, input)
        },
        {
            name: 'From Base64',
            description: 'Decode Base64 to text',
            run: (input) => safeOp(atob, input)
        },
        {
            name: 'To Hex',
            description: 'Convert text to Hex',
            run: (input) => {
                let result = '';
                for (let i = 0; i < input.length; i++) {
                    result += input.charCodeAt(i).toString(16).padStart(2, '0') + ' ';
                }
                return result.trim();
            }
        },
        {
            name: 'From Hex',
            description: 'Convert Hex to text',
            run: (input) => {
                const hex = input.replace(/\s/g, '');
                let str = '';
                for (let i = 0; i < hex.length; i += 2) {
                    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
                }
                return str;
            }
        },
        {
            name: 'To Binary',
            description: 'Convert text to Binary',
            run: (input) => input.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' ')
        },
        {
            name: 'From Binary',
            description: 'Convert Binary to text',
            run: (input) => input.split(' ').map(b => String.fromCharCode(parseInt(b, 2))).join('')
        },
        {
            name: 'To Decimal',
            description: 'Convert text to Decimal',
            run: (input) => input.split('').map(c => c.charCodeAt(0)).join(' ')
        },
        {
            name: 'From Decimal',
            description: 'Convert Decimal to text',
            run: (input) => input.split(' ').map(d => String.fromCharCode(parseInt(d))).join('')
        }
    ],
    'Encryption / Encoding': [
        {
            name: 'ROT13',
            description: 'Rotate characters by 13',
            run: (input) => input.replace(/[a-zA-Z]/g, (c) => {
                const base = c <= 'Z' ? 65 : 97;
                return String.fromCharCode((c.charCodeAt(0) - base + 13) % 26 + base);
            })
        },
        {
            name: 'URL Encode',
            description: 'Encode for URLs',
            run: (input) => encodeURIComponent(input)
        },
        {
            name: 'URL Decode',
            description: 'Decode URL strings',
            run: (input) => decodeURIComponent(input)
        },
        {
            name: 'HTML Entity Encode',
            description: 'Encode HTML entities',
            run: (input) => input.replace(/[\u00A0-\u9999<>\&]/g, (i) => '&#' + i.charCodeAt(0) + ';')
        },
        {
            name: 'HTML Entity Decode',
            description: 'Decode HTML entities',
            run: (input) => {
                const txt = document.createElement('textarea');
                txt.innerHTML = input;
                return txt.value;
            }
        },
        {
            name: 'XOR',
            description: 'XOR with key (default 42)',
            run: (input) => {
                const key = 42;
                return input.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ key)).join('');
            }
        }
    ],
    'Hashing': [
        {
            name: 'MD5',
            description: 'MD5 Hash',
            run: (input) => CryptoJS.MD5(input).toString()
        },
        {
            name: 'SHA1',
            description: 'SHA1 Hash',
            run: (input) => CryptoJS.SHA1(input).toString()
        },
        {
            name: 'SHA256',
            description: 'SHA256 Hash',
            run: (input) => CryptoJS.SHA256(input).toString()
        },
        {
            name: 'SHA512',
            description: 'SHA512 Hash',
            run: (input) => CryptoJS.SHA512(input).toString()
        }
    ],
    'Code tidy': [
        {
            name: 'JSON Beautify',
            description: 'Format JSON',
            run: (input) => safeOp(() => JSON.stringify(JSON.parse(input), null, 2))
        },
        {
            name: 'JSON Minify',
            description: 'Compact JSON',
            run: (input) => safeOp(() => JSON.stringify(JSON.parse(input)))
        },
        {
            name: 'XML Beautify',
            description: 'Simple XML Indenter',
            run: (input) => {
                let formatted = '';
                let pad = 0;
                input.split(/>\s*</).forEach(node => {
                    if (node.match(/^\/\w/)) pad -= 1;
                    formatted += new Array(pad + 1).join('  ') + '<' + node + '>\r\n';
                    if (node.match(/^<?\w[^>]*[^\/]$/) && !node.startsWith("?")) pad += 1;
                });
                return formatted.substring(1, formatted.length - 3);
            }
        }
    ],
    'Utils': [
        {
            name: 'Reverse',
            description: 'Reverse string',
            run: (input) => input.split('').reverse().join('')
        },
        {
            name: 'Upper Case',
            description: 'Convert to UPPER CASE',
            run: (input) => input.toUpperCase()
        },
        {
            name: 'Lower Case',
            description: 'Convert to lower case',
            run: (input) => input.toLowerCase()
        },
        {
            name: 'Count Characters',
            description: 'Count length',
            run: (input) => `Length: ${input.length}`
        },
        {
            name: 'Word Count',
            description: 'Count words',
            run: (input) => `Words: ${input.trim().split(/\s+/).length}`
        }
    ],
    'Networking': [
        {
            name: 'Defang IP',
            description: 'Defang IP addresses (1.1.1.1 -> 1.1.1[.]1)',
            run: (input) => input.replace(/\./g, '[.]')
        },
        {
            name: 'Refang IP',
            description: 'Refang IP addresses',
            run: (input) => input.replace(/\[\.\]/g, '.')
        }
    ]
};

// Flatten for easy lookup by name
export const operations = {};
Object.keys(categories).forEach(cat => {
    categories[cat].forEach(op => {
        operations[op.name] = op;
    });
});

export const runRecipe = (input, recipe) => {
    let output = input;
    for (const opName of recipe) {
        const op = operations[opName];
        if (op) {
            output = op.run(output);
        }
    }
    return output;
};
