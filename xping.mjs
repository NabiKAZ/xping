#!/usr/bin/env node

import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import chalk from 'chalk';
import { Command } from 'commander';
import net from 'net';

const execAsync = promisify(exec);

// Configuration constants
const XRAY_PATH = process.env.XPING_XRAY_PATH || 'xray';
const TARGET_URL = process.env.XPING_TARGET_URL || 'https://www.google.com/generate_204';
const FRAGMENT_PACKETS = process.env.XPING_FRAGMENT_PACKETS || "tlshello";
const FRAGMENT_LENGTH = process.env.XPING_FRAGMENT_LENGTH || "5-9";
const FRAGMENT_INTERVAL = process.env.XPING_FRAGMENT_INTERVAL || "1-2";

// Function to find a free port
function findFreePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.listen(0, (err) => {
            if (err) {
                reject(err);
            } else {
                const port = server.address().port;
                server.close(() => {
                    resolve(port);
                });
            }
        });
    });
}

// Function to check if xray is available
async function checkXrayAvailable() {
    try {
        // Try the specified XRAY_PATH first
        await execAsync(`"${XRAY_PATH}" version`);
        return XRAY_PATH;
    } catch (error) {
        // Try system PATH as fallback
        try {
            await execAsync('xray version');
            return 'xray';
        } catch (e) {
            return false;
        }
    }
}

// Function to parse vless URL
function parseVlessUrl(vlessUrl) {
    try {
        // Remove vless:// prefix
        const urlWithoutProtocol = vlessUrl.replace('vless://', '');

        // Split at @ to separate uuid and server info
        const [uuid, serverPart] = urlWithoutProtocol.split('@');

        // Split server part to get address, port and parameters
        const [serverAndPort, paramsPart] = serverPart.split('?');
        const [address, port] = serverAndPort.split(':');

        // Parse parameters
        const params = new URLSearchParams(paramsPart.split('#')[0]);

        return {
            uuid: uuid,
            address: address,
            port: parseInt(port),
            encryption: params.get('encryption') || 'none',
            security: params.get('security') || 'tls',
            sni: params.get('sni') || '',
            fp: params.get('fp') || '',
            type: params.get('type') || 'ws',
            host: params.get('host') || '',
            path: params.get('path') || '/',
            remark: decodeURIComponent(paramsPart.split('#')[1] || 'vless-config')
        };
    } catch (error) {
        throw new Error(`Failed to parse vless URL: ${error.message}`);
    }
}

// Function to generate xray config
function generateXrayConfig(vlessConfig, fragmentEnabled = false, proxyPort = 10801) {
    const config = {
        "log": {
            "loglevel": "error"
        },
        "dns": {
            "servers": [
                "8.8.8.8",
                "1.1.1.1"
            ]
        },
        "inbounds": [
            {
                "tag": "http-proxy",
                "port": proxyPort,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {
                    "auth": "noauth",
                    "allowTransparent": false
                }
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": vlessConfig.address,
                            "port": vlessConfig.port,
                            "users": [
                                {
                                    "id": vlessConfig.uuid,
                                    "email": "ping@test.com",
                                    "security": "auto",
                                    "encryption": vlessConfig.encryption
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": vlessConfig.type,
                    "security": vlessConfig.security,
                    "tlsSettings": vlessConfig.security === "tls" ? {
                        "allowInsecure": false,
                        "serverName": vlessConfig.sni,
                        "fingerprint": vlessConfig.fp
                    } : undefined,
                    "wsSettings": vlessConfig.type === "ws" ? {
                        "path": vlessConfig.path,
                        "headers": {
                            "Host": vlessConfig.host
                        }
                    } : undefined,
                    "sockopt": fragmentEnabled ? {
                        "dialerProxy": "fragment"
                    } : undefined
                },
                "mux": {
                    "enabled": false,
                    "concurrency": 8
                }
            },
            {
                "tag": "direct",
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "AsIs",
                    "userLevel": 0
                }
            },
            {
                "tag": "fragment",
                "protocol": "freedom",
                "settings": fragmentEnabled ? {
                    "fragment": {
                        "packets": FRAGMENT_PACKETS,
                        "length": FRAGMENT_LENGTH,
                        "interval": FRAGMENT_INTERVAL
                    }
                } : {}
            }
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "outboundTag": "proxy",
                    "domain": [""]
                }
            ]
        }
    };

    return config;
}

// Function to get current time string
function getCurrentTimeString() {
    const now = new Date();
    return now.toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

// Function to test connection with fetch through proxy
function testConnection(proxyPort, timeout = 10000) {
    return new Promise(async (resolve, reject) => {
        try {
            // Use undici for proxy support
            const { ProxyAgent, fetch } = await import('undici');
            const proxyAgent = new ProxyAgent(`http://127.0.0.1:${proxyPort}`);
            const response = await fetch(TARGET_URL, {
                method: 'HEAD',
                dispatcher: proxyAgent,
                signal: AbortSignal.timeout(timeout)
            });

            resolve({
                success: true,
                statusCode: response.status,
                output: `HTTP/${response.status}`
            });

        } catch (error) {
            reject({
                success: false,
                error: error.message
            });
        }
    });
}

// Function to detect input type and load config
function detectInputTypeAndLoadConfig(input) {
    // Check if input is a vless URL
    if (input.startsWith('vless://')) {
        return {
            type: 'vless',
            config: parseVlessUrl(input)
        };
    }

    // Check if input is a file path
    const filePath = resolve(input);
    if (existsSync(filePath)) {
        try {
            const fileContent = readFileSync(filePath, 'utf8');
            const xrayConfig = JSON.parse(fileContent);

            // Extract connection info from xray config for display
            const outbound = xrayConfig.outbounds?.find(o => o.protocol === 'vless' || o.protocol === 'vmess' || o.protocol === 'trojan');
            if (!outbound) {
                throw new Error('No valid proxy outbound found in config file');
            }

            const connectionInfo = extractConnectionInfo(outbound);

            return {
                type: 'config',
                config: connectionInfo
            };
        } catch (error) {
            throw new Error(`Failed to read config file: ${error.message}`);
        }
    }

    throw new Error('Input must be either a vless:// URL or a valid xray config file path');
}

// Function to extract connection info from xray outbound for display
function extractConnectionInfo(outbound) {
    const vnext = outbound.settings?.vnext?.[0];
    const streamSettings = outbound.streamSettings || {};

    return {
        address: vnext?.address || 'unknown',
        port: vnext?.port || 'unknown',
        protocol: outbound.protocol || 'unknown',
        security: streamSettings.security || 'none',
        network: streamSettings.network || 'tcp',
        remark: outbound.tag || 'config-file'
    };
}

// Function to detect fragment settings in config file
function detectFragmentInConfig(xrayConfig) {
    // Check if any outbound has fragment settings
    const fragmentOutbounds = xrayConfig.outbounds?.filter(outbound =>
        outbound.settings?.fragment ||
        (outbound.protocol === 'freedom' && outbound.settings?.fragment)
    );

    if (fragmentOutbounds && fragmentOutbounds.length > 0) {
        const fragmentConfig = fragmentOutbounds[0].settings.fragment;
        return {
            enabled: true,
            packets: fragmentConfig.packets || 'unknown',
            length: fragmentConfig.length || 'unknown',
            interval: fragmentConfig.interval || 'unknown'
        };
    }

    // Check if main proxy outbound uses fragment via dialerProxy
    const proxyOutbound = xrayConfig.outbounds?.find(o =>
        o.protocol === 'vless' || o.protocol === 'vmess' || o.protocol === 'trojan'
    );

    if (proxyOutbound?.streamSettings?.sockopt?.dialerProxy) {
        const dialerProxyTag = proxyOutbound.streamSettings.sockopt.dialerProxy;
        const dialerOutbound = xrayConfig.outbounds?.find(o => o.tag === dialerProxyTag);

        if (dialerOutbound?.settings?.fragment) {
            const fragmentConfig = dialerOutbound.settings.fragment;
            return {
                enabled: true,
                packets: fragmentConfig.packets || 'unknown',
                length: fragmentConfig.length || 'unknown',
                interval: fragmentConfig.interval || 'unknown'
            };
        }
    }

    return { enabled: false };
}

// Function to validate xray config
async function validateXrayConfig(xrayPath, configData) {
    try {
        const cmd = xrayPath === 'xray' ? 'xray' : `"${xrayPath}"`;

        // If configData is a file path (string without JSON structure)
        if (typeof configData === 'string' && !configData.trim().startsWith('{')) {
            // Use file path method for existing files
            const { stdout, stderr } = await execAsync(`${cmd} -test -config "${configData}"`);
            return { valid: true, message: 'Config is valid' };
        }

        // Use stdin for config validation
        const xrayProcess = spawn(cmd === 'xray' ? 'xray' : xrayPath, ['-test', '-config', 'stdin:'], {
            stdio: ['pipe', 'pipe', 'pipe']
        });

        return new Promise((resolve) => {
            let stdout = '';
            let stderr = '';

            xrayProcess.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            xrayProcess.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            xrayProcess.on('close', (code) => {
                if (code === 0) {
                    resolve({ valid: true, message: 'Config is valid' });
                } else {
                    const errorMessage = stderr.trim() || stdout.trim() || 'Invalid config format';
                    resolve({ valid: false, message: errorMessage });
                }
            });

            // Send config via stdin
            if (typeof configData === 'string') {
                xrayProcess.stdin.write(configData);
            } else {
                xrayProcess.stdin.write(JSON.stringify(configData, null, 2));
            }
            xrayProcess.stdin.end();
        });

    } catch (error) {
        return {
            valid: false,
            message: error.stderr?.trim() || error.stdout?.trim() || error.message || 'Invalid config format'
        };
    }
}

// Main function
async function main() {
    const program = new Command();

    program
        .name('xping')
        .description('VLESS connection ping tool using Xray with fragment support\nProject: https://github.com/NabiKAZ/xping')
        .argument('<input>', 'VLESS URL or xray config file path to test')
        .option('-f, --fragment', 'Enable fragment mode')
        .option('-d, --delay <ms>', 'Delay between pings in milliseconds', '1000')
        .option('-t, --timeout <ms>', 'Connection timeout in milliseconds', '10000')
        .option('-c, --count <number>', 'Number of pings to send (default: infinite)')
        .version('1.0.0', '-v, --version', 'output the version number')
        .helpOption('-h, --help', 'Display help for command')
        .addHelpText('after', `
Examples:
  $ node ping3.mjs "vless://uuid@server:port?security=tls&type=ws&path=/..."
  $ node ping3.mjs config.json --fragment --count 10
  $ node ping3.mjs "vless://..." --delay 500 --timeout 10000 --count 5
  $ node ping3.mjs config.json -c 3 -d 2000 -t 5000

Environment Variables:
  XPING_XRAY_PATH          Path to xray binary (default: xray)
  XPING_TARGET_URL         Target URL for testing (default: https://www.google.com/generate_204)
  XPING_FRAGMENT_PACKETS   Fragment packets type (default: tlshello)
  XPING_FRAGMENT_LENGTH    Fragment length range (default: 5-9)
  XPING_FRAGMENT_INTERVAL  Fragment interval range (default: 1-2)

Note: 
  - When using a config file, it will be processed in memory with a free port (original file unchanged)
  - Fragment mode is only applied to vless URLs, not config files
        `);

    program.parse();

    const options = program.opts();
    const input = program.args[0];

    // Set configuration from options
    const fragmentEnabled = options.fragment; // Default is false, enabled with --fragment
    const delay = parseInt(options.delay);
    const timeout = parseInt(options.timeout);
    const pingCount = options.count ? parseInt(options.count) : null; // null means infinite

    try {
        console.log('');

        // Check if xray is available
        const xrayPath = await checkXrayAvailable();
        if (!xrayPath) {
            console.log(chalk.red('❌ Xray not found!'));
            console.log(chalk.yellow(`💡 Searched for: ${XRAY_PATH} (from XPING_XRAY_PATH env var or default)`));
            console.log(chalk.blue('📥 Download: https://github.com/XTLS/Xray-core/releases'));
            process.exit(1);
        }

        // Find a free port for proxy
        let proxyPort = await findFreePort();
        
        // Detect input type and load config
        const inputData = detectInputTypeAndLoadConfig(input);
        const connectionInfo = inputData.config;

        let xrayConfig;
        let configFilePath = null;
        let configFragmentInfo = null;

        if (inputData.type === 'vless') {
            xrayConfig = generateXrayConfig(connectionInfo, fragmentEnabled, proxyPort);

            // Validate generated config via stdin
            const validation = await validateXrayConfig(xrayPath, xrayConfig);

            if (!validation.valid) {
                console.log(chalk.red(`❌ Generated config validation failed:`));
                console.log(chalk.red(validation.message));
                process.exit(1);
            }
            console.log(chalk.green('✅ Generated config validation passed'));
        } else {
            // Load and modify existing config file to use our free port
            configFilePath = resolve(input);

            // Read and parse the config file
            const fileContent = readFileSync(configFilePath, 'utf8');
            const fullXrayConfig = JSON.parse(fileContent);
            configFragmentInfo = detectFragmentInConfig(fullXrayConfig);
            
            // Modify the config to use our free port instead of the original port
            if (fullXrayConfig.inbounds) {
                fullXrayConfig.inbounds.forEach(inbound => {
                    if (inbound.protocol === 'http' || inbound.protocol === 'mixed' || inbound.protocol === 'socks') {
                        inbound.port = proxyPort;
                        inbound.listen = "127.0.0.1"; // Ensure it's localhost only
                    }
                });
            }

            // We'll use the modified config via stdin instead of file path
            xrayConfig = fullXrayConfig;
            configFilePath = null; // Don't use file path, use stdin instead

            // Validate the modified config
            const validation = await validateXrayConfig(xrayPath, xrayConfig);
            if (!validation.valid) {
                console.log(chalk.red(`❌ Config validation failed:`));
                console.log(chalk.red(validation.message));
                process.exit(1);
            }
            console.log(chalk.green('✅ Config validation passed'));
        }

        // Show config information
        console.log(chalk.cyanBright(`📍 ${connectionInfo.address}:${connectionInfo.port}`) + chalk.gray(' | ') + chalk.white(connectionInfo.remark));

        if (inputData.type === 'vless') {
            console.log(chalk.cyanBright(`🔒 ${connectionInfo.security}`) + chalk.gray(' | SNI: ') + chalk.yellow(connectionInfo.sni) + chalk.gray(' | Path: ') + chalk.yellow(connectionInfo.path));
        } else {
            console.log(chalk.cyanBright(`🔒 ${connectionInfo.security}`) + chalk.gray(' | Network: ') + chalk.yellow(connectionInfo.network) + chalk.gray(' | Protocol: ') + chalk.yellow(connectionInfo.protocol));
        }

        // Show fragment info
        let fragmentInfo;
        if (inputData.type === 'vless') {
            fragmentInfo = fragmentEnabled ? {
                enabled: true,
                packets: FRAGMENT_PACKETS,
                length: FRAGMENT_LENGTH,
                interval: FRAGMENT_INTERVAL
            } : { enabled: false };
        } else {
            fragmentInfo = configFragmentInfo || { enabled: false };
        }

        if (fragmentInfo.enabled) {
            console.log(chalk.cyanBright(`📝 Fragment: `) + chalk.gray('packets: ') + chalk.yellow(fragmentInfo.packets) + chalk.gray(', length: ') + chalk.yellow(fragmentInfo.length) + chalk.gray(', interval: ') + chalk.yellow(fragmentInfo.interval));
        } else {
            console.log(chalk.cyanBright(`📝 Fragment: `) + chalk.gray('disabled'));
        }
        console.log('');

        // Start xray process with config via stdin
        const xrayArgs = ['-config', 'stdin:'];
        xrayProcess = spawn(xrayPath === true ? 'xray' : xrayPath, xrayArgs, {
            stdio: 'pipe'
        });

        // Handle xray process errors
        xrayProcess.on('error', (error) => {
            console.log(chalk.red(`❌ Failed to start xray: ${error.message}`));
            process.exit(1);
        });
       
        // Send config to xray via stdin (both vless and modified config file)
        if (xrayConfig) {
            xrayProcess.stdin.write(JSON.stringify(xrayConfig, null, 2));
            xrayProcess.stdin.end();
        }

        let xrayStarted = false;
        let xrayError = false;
        let xrayErrorMessages = [];
        let xrayOutputMessages = [];
        let processExited = false;

        xrayProcess.stdout.on('data', (data) => {
            const output = data.toString();
            xrayOutputMessages.push(output.trim());
            // Check for various signs that xray has started successfully
            if (output.includes('started') ||
                output.includes('listening') ||
                output.includes('A unified platform for anti-censorship') ||
                (output.includes('Xray') && output.includes('windows/amd64'))) {
                xrayStarted = true;
            }
        });

        xrayProcess.stderr.on('data', (data) => {
            const error = data.toString().trim();
            if (error) {
                xrayErrorMessages.push(error);
                // Also immediately show critical errors
                if (error.includes('Failed to start') ||
                    error.includes('failed to listen') ||
                    error.includes('bind:') ||
                    error.includes('address already in use') ||
                    error.includes('permission denied') ||
                    error.includes('invalid config') ||
                    error.includes('parse') ||
                    error.includes('cannot') ||
                    error.includes('error')) {
                    console.log(chalk.red(`❌ Xray error: ${error}`));
                }
                xrayError = true;
            }
        });

        xrayProcess.on('exit', (code) => {
            processExited = true;

            if (code !== 0 && code !== null) {
                console.log(chalk.red(`❌ Xray exited with code: ${code}`));

                if (xrayErrorMessages.length > 0) {
                    console.log(chalk.red('📝 Error details:'));
                    xrayErrorMessages.forEach(msg => {
                        console.log(chalk.red(`   ${msg}`));
                    });
                } else if (xrayOutputMessages.length > 0) {
                    console.log(chalk.red('📋 Xray output messages:'));
                    xrayOutputMessages.forEach(msg => {
                        if (msg.trim()) {
                            console.log(chalk.red(`${msg}`));
                        }
                    });
                } else {
                    console.log(chalk.red('📝 No specific error message available'));
                }
                process.exit(1);
            }
        });

        // Wait for xray to start or fail with better timing
        let attempts = 0;
        const maxAttempts = 6; // 3 seconds total, enough time for startup
        while (attempts < maxAttempts && !xrayStarted && !processExited) {
            await new Promise(resolve => setTimeout(resolve, 500));
            attempts++;

            // Check if we have errors during waiting
            if (xrayError && xrayErrorMessages.length > 0) {
                break;
            }
        }

        // Check final status
        if (processExited || xrayError) {
            if (!processExited) {
                // Process is still running but has errors
                console.log(chalk.red('❌ Xray startup errors detected:'));
                xrayErrorMessages.forEach(msg => {
                    console.log(chalk.red(`   ${msg}`));
                });
                xrayProcess.kill();
            }
            process.exit(1);
        }

        if (!xrayStarted) {
            console.log(chalk.red('❌ Xray failed to start within timeout period'));

            if (xrayErrorMessages.length > 0) {
                console.log(chalk.red('📝 Error messages received:'));
                xrayErrorMessages.forEach(msg => {
                    console.log(chalk.red(`   ${msg}`));
                });
            } else if (xrayOutputMessages.length > 0) {
                console.log(chalk.yellow('📋 Output messages received:'));
                xrayOutputMessages.forEach(msg => {
                    if (msg.trim()) {
                        console.log(chalk.yellow(`   ${msg}`));
                    }
                });
            } else {
                console.log(chalk.red('📝 No output received from Xray during startup'));
            }

            xrayProcess.kill();
            process.exit(1);
        }

        let currentPing = 0;

        // Ping loop - infinite or limited by count
        while (pingCount === null || currentPing < pingCount) {
            currentPing++;
            try {
                // Show testing message and get result in one line
                process.stdout.write(chalk.gray(`🌐 [${getCurrentTimeString()}] Testing connection to ${TARGET_URL}...`));

                const startTime = Date.now();
                const result = await testConnection(proxyPort, timeout);
                const endTime = Date.now();
                const responseTime = endTime - startTime;

                // Clear the testing line and show result
                process.stdout.write('\r\x1b[K'); // Clear current line

                // Update statistics only after successful test
                pingStats.count = currentPing;
                pingStats.success++;
                pingStats.total += responseTime;
                pingStats.min = Math.min(pingStats.min, responseTime);
                pingStats.max = Math.max(pingStats.max, responseTime);

                // Calculate success rate
                const successRate = Math.round((pingStats.success / pingStats.count) * 100);

                // Format output with more info
                console.log(chalk.gray(`[${getCurrentTimeString()}]`) + chalk.green(` ✅ ${connectionInfo.address}:${connectionInfo.port} responded in `) + chalk.bold.whiteBright(`${responseTime}ms`));

            } catch (error) {
                // Clear the testing line and show timeout
                process.stdout.write('\r\x1b[K'); // Clear current line

                // Update statistics only after failed test
                pingStats.count = currentPing;
                const successRate = Math.round((pingStats.success / pingStats.count) * 100);

                // Extract error reason
                let errorReason = 'Request timeout';
                if (error.error) {
                    if (error.error.includes('fetch failed')) errorReason = 'Connection failed';
                    else if (error.error.includes('timeout')) errorReason = 'Request timeout';
                    else if (error.error.includes('ECONNREFUSED')) errorReason = 'Connection refused';
                    else if (error.error.includes('ENOTFOUND')) errorReason = 'Host not found';
                    else errorReason = 'Network error';
                }

                console.log(chalk.gray(`[${getCurrentTimeString()}]`) + chalk.red(` ❌ ${errorReason}`));
            }

            // Wait before next ping (but not after the last ping)
            if (pingCount === null || currentPing < pingCount) {
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }

        // Show final statistics if count was specified
        if (pingCount !== null) {
            showPingStatistics();
        }

        // Clean up
        xrayProcess.kill();

    } catch (error) {
        console.log(chalk.red(`❌ Error: ${error.message}`));
        process.exit(1);
    }
}

// Handle process termination
let xrayProcess = null;
let pingStats = { count: 0, success: 0, total: 0, min: Infinity, max: 0 };

function showPingStatistics() {
    console.log(chalk.blue('\n📊 === Statistics ==='));
    console.log(chalk.white(`📦 Sent: `) + chalk.cyan(pingStats.count) + chalk.white(` | Received: `) + chalk.green(pingStats.success) + chalk.white(` | Lost: `) + chalk.red(pingStats.count - pingStats.success) + chalk.yellow(` (${Math.round(((pingStats.count - pingStats.success) / pingStats.count) * 100) || 0}% loss)`));

    if (pingStats.success > 0) {
        const avgTime = Math.round(pingStats.total / pingStats.success);
        console.log(chalk.white(`⏱️  Min: `) + chalk.green(`${pingStats.min}ms`) + chalk.white(` | Max: `) + chalk.red(`${pingStats.max}ms`) + chalk.white(` | Avg: `) + chalk.yellow(`${avgTime}ms`));
    }
    console.log(chalk.magenta('🏁 Completed!'));
}

process.on('SIGINT', () => {
    // Clear any pending testing message
    process.stdout.write('\r\x1b[K');
    console.log(chalk.yellow('\n^C'));
    showPingStatistics();
    if (xrayProcess) {
        xrayProcess.kill();
    }
    process.exit(0);
});

process.on('SIGTERM', () => {
    // Clear any pending testing message
    process.stdout.write('\r\x1b[K');
    console.log(chalk.yellow('\nProcess terminated'));
    showPingStatistics();
    if (xrayProcess) {
        xrayProcess.kill();
    }
    process.exit(0);
});

// Run the main function
main().catch(error => {
    console.error(chalk.red('💥 Unexpected error:'), error.message);
    process.exit(1);
});
