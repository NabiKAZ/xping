#!/usr/bin/env node

/**
 * XPing - Multi-Protocol Connection Ping Tool
 * 
 * Test proxy connections (VLESS, VMESS, Shadowsocks, Trojan) using Xray core.
 * Features: Fragment mode, auto port detection, real-time stats, config file support.
 * 
 * Usage:
 *  xping "vless://uuid@server:port?security=tls"
 *  xping "vmess://base64-config"
 *  xping "ss://method:password@server:port"
 *  xping "trojan://password@server:port"
 *  xping config.json --fragment -c 10
 * 
 * Environment Variables:
 *  XPING_XRAY_PATH          : Path to xray binary (default: xray)
 *  XPING_TARGET_URL         : Target URL for testing (default: https://www.google.com/generate_204)
 *  XPING_FRAGMENT_PACKETS   : Fragment packets type (default: tlshello)
 *  XPING_FRAGMENT_LENGTH    : Fragment length range (default: 5-9)
 *  XPING_FRAGMENT_INTERVAL  : Fragment interval range (default: 1-2)
 * 
 * @repository https://github.com/NabiKAZ/xping
 * @author NabiKAZ <https://x.com/NabiKAZ>
 * @license GPL-3.0
 * @version 2.0.0
 */

import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import chalk from 'chalk';
import yargs from 'yargs';
import { hideBin } from 'yargs/helpers';
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
        const cleanPath = String(XRAY_PATH).replace(/^["']|["']$/g, '');
        await execAsync(`"${cleanPath}" version`);
        return cleanPath;
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

// Helper function to safely decode URI component
function safeDecodeURIComponent(value = '') {
    try {
        return decodeURIComponent(value);
    } catch {
        return value;
    }
}

// Helper function to decode Base64
function decodeBase64(input) {
    let normalized = String(input || '').replace(/-/g, '+').replace(/_/g, '/').trim();
    while (normalized.length % 4 !== 0) normalized += '=';
    return Buffer.from(normalized, 'base64').toString('utf8');
}

// Helper function to split URL and remark
function splitUrlAndRemark(rawUrl, scheme) {
    const body = rawUrl.slice(`${scheme}://`.length);
    const hashIndex = body.indexOf('#');
    if (hashIndex === -1) {
        return { base: rawUrl, remark: `${scheme}-config` };
    }
    const baseBody = body.slice(0, hashIndex);
    const remark = safeDecodeURIComponent(body.slice(hashIndex + 1)) || `${scheme}-config`;
    return { base: `${scheme}://${baseBody}`, remark };
}

// Helper function to parse JSON safely
function parseMaybeJson(value, fallback = {}) {
    if (!value) return fallback;
    try {
        return JSON.parse(value);
    } catch {
        return fallback;
    }
}

// Helper function to build common stream settings
function buildCommonStreamSettings(config, fragmentEnabled) {
    const streamSettings = {
        network: config.type || 'tcp',
        security: config.security || 'none',
        sockopt: fragmentEnabled ? { dialerProxy: 'fragment' } : undefined
    };

    if (config.security === 'tls') {
        streamSettings.tlsSettings = {
            allowInsecure: false,
            serverName: config.sni || config.host || undefined,
            fingerprint: config.fp || undefined,
            alpn: config.alpn || undefined
        };
    } else if (config.security === 'reality') {
        streamSettings.realitySettings = {
            serverName: config.sni || config.serverName || undefined,
            fingerprint: config.fp || 'chrome',
            publicKey: config.pbk || undefined,
            shortId: config.sid || undefined,
            spiderX: config.spx || undefined
        };
    }

    if (streamSettings.network === 'ws') {
        streamSettings.wsSettings = {
            path: config.path || '/',
            headers: config.host ? { Host: config.host } : undefined
        };
    }

    if (streamSettings.network === 'grpc') {
        streamSettings.grpcSettings = {
            serviceName: config.serviceName || config.path || '',
            multiMode: config.mode === 'multi'
        };
    }

    if (streamSettings.network === 'tcp' && config.headerType === 'http') {
        streamSettings.tcpSettings = {
            header: {
                type: 'http',
                request: {
                    version: '1.1',
                    method: 'GET',
                    path: [config.path || '/'],
                    headers: {
                        Host: config.host ? [config.host] : [''],
                        'User-Agent': [
                            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
                        ],
                        'Accept-Encoding': ['gzip, deflate'],
                        Connection: ['keep-alive'],
                        Pragma: ['no-cache']
                    }
                }
            }
        };
    }

    return streamSettings;
}

// Function to parse vless URL
function parseVlessUrl(vlessUrl) {
    try {
        const { base, remark } = splitUrlAndRemark(vlessUrl, 'vless');
        const url = new URL(base);

        return {
            protocol: 'vless',
            uuid: decodeURIComponent(url.username),
            address: url.hostname,
            port: Number(url.port),
            encryption: url.searchParams.get('encryption') || 'none',
            security: url.searchParams.get('security') || 'tls',
            sni: url.searchParams.get('sni') || '',
            fp: url.searchParams.get('fp') || '',
            type: url.searchParams.get('type') || 'ws',
            headerType: url.searchParams.get('headerType') || '',
            host: url.searchParams.get('host') || '',
            path: url.searchParams.get('path') || '/',
            serviceName: url.searchParams.get('serviceName') || '',
            mode: url.searchParams.get('mode') || '',
            pbk: url.searchParams.get('pbk') || '',
            sid: url.searchParams.get('sid') || '',
            spx: url.searchParams.get('spx') || '',
            alpn: (url.searchParams.get('alpn') || '').split(',').filter(Boolean),
            remark
        };
    } catch (error) {
        throw new Error(`Failed to parse VLESS URL: ${error.message}`);
    }
}

// Function to parse vmess URL
function parseVmessUrl(vmessUrl) {
    try {
        const encoded = vmessUrl.slice('vmess://'.length).trim();
        const decoded = decodeBase64(encoded);
        const data = JSON.parse(decoded);

        return {
            protocol: 'vmess',
            uuid: data.id,
            address: data.add,
            port: Number(data.port),
            aid: Number(data.aid || 0),
            scy: data.scy || 'auto',
            security: data.tls === 'tls' ? 'tls' : (data.security || 'none'),
            sni: data.sni || data.host || '',
            fp: data.fp || '',
            type: data.net || 'tcp',
            headerType: data.type || '',
            host: data.host || '',
            path: data.path || '/',
            serviceName: data.path || '',
            mode: data.mode || '',
            alpn: data.alpn ? String(data.alpn).split(',').filter(Boolean) : [],
            remark: data.ps || 'vmess-config'
        };
    } catch (error) {
        throw new Error(`Failed to parse VMESS URL: ${error.message}`);
    }
}

// Function to parse ss URL
function parseSsUrl(ssUrl) {
    try {
        const { base, remark } = splitUrlAndRemark(ssUrl, 'ss');
        const body = base.slice('ss://'.length);
        const queryIndex = body.indexOf('?');
        const mainPart = queryIndex === -1 ? body : body.slice(0, queryIndex);
        const queryPart = queryIndex === -1 ? '' : body.slice(queryIndex + 1);
        const pluginParams = new URLSearchParams(queryPart);

        let credsPart = mainPart;
        let serverPart = '';

        if (mainPart.includes('@')) {
            [credsPart, serverPart] = mainPart.split('@');
        } else {
            const decoded = decodeBase64(mainPart);
            const atIndex = decoded.lastIndexOf('@');
            if (atIndex === -1) throw new Error('Invalid SS config format');
            credsPart = decoded.slice(0, atIndex);
            serverPart = decoded.slice(atIndex + 1);
        }

        const credsDecoded = credsPart.includes(':') ? credsPart : decodeBase64(credsPart);
        const firstColon = credsDecoded.indexOf(':');
        if (firstColon === -1) throw new Error('Invalid SS credentials');

        const method = credsDecoded.slice(0, firstColon);
        const password = credsDecoded.slice(firstColon + 1);
        const serverMatch = serverPart.match(/^(.+):([0-9]+)$/);
        if (!serverMatch) throw new Error('Invalid SS server:port');

        return {
            protocol: 'shadowsocks',
            address: serverMatch[1],
            port: Number(serverMatch[2]),
            method,
            password,
            plugin: pluginParams.get('plugin') || '',
            pluginOpts: pluginParams.get('plugin-opts') || '',
            remark
        };
    } catch (error) {
        throw new Error(`Failed to parse SS URL: ${error.message}`);
    }
}

// Function to parse trojan URL
function parseTrojanUrl(trojanUrl) {
    try {
        const { base, remark } = splitUrlAndRemark(trojanUrl, 'trojan');
        const url = new URL(base);

        return {
            protocol: 'trojan',
            password: decodeURIComponent(url.username),
            address: url.hostname,
            port: Number(url.port),
            security: url.searchParams.get('security') || 'tls',
            sni: url.searchParams.get('sni') || '',
            fp: url.searchParams.get('fp') || '',
            type: url.searchParams.get('type') || 'tcp',
            headerType: url.searchParams.get('headerType') || '',
            host: url.searchParams.get('host') || '',
            path: url.searchParams.get('path') || '/',
            serviceName: url.searchParams.get('serviceName') || '',
            mode: url.searchParams.get('mode') || '',
            alpn: (url.searchParams.get('alpn') || '').split(',').filter(Boolean),
            remark
        };
    } catch (error) {
        throw new Error(`Failed to parse TROJAN URL: ${error.message}`);
    }
}

// Function to detect and parse any config URL
function parseConfigUrl(configUrl) {
    if (configUrl.startsWith('vless://')) return parseVlessUrl(configUrl);
    if (configUrl.startsWith('vmess://')) return parseVmessUrl(configUrl);
    if (configUrl.startsWith('ss://')) return parseSsUrl(configUrl);
    if (configUrl.startsWith('trojan://')) return parseTrojanUrl(configUrl);
    throw new Error('Unsupported protocol');
}

// Function to generate xray config
function generateXrayConfig(config, fragmentEnabled = false, proxyPort = 10801) {
    let proxyOutbound;

    if (config.protocol === 'vless') {
        proxyOutbound = {
            tag: 'proxy',
            protocol: 'vless',
            settings: {
                vnext: [{
                    address: config.address,
                    port: config.port,
                    users: [{
                        id: config.uuid,
                        email: 'ping@test.com',
                        security: 'auto',
                        encryption: config.encryption || 'none'
                    }]
                }]
            },
            streamSettings: buildCommonStreamSettings(config, fragmentEnabled),
            mux: { enabled: false, concurrency: 8 }
        };
    } else if (config.protocol === 'vmess') {
        proxyOutbound = {
            tag: 'proxy',
            protocol: 'vmess',
            settings: {
                vnext: [{
                    address: config.address,
                    port: config.port,
                    users: [{
                        id: config.uuid,
                        alterId: config.aid || 0,
                        security: config.scy || 'auto'
                    }]
                }]
            },
            streamSettings: buildCommonStreamSettings(config, fragmentEnabled),
            mux: { enabled: false, concurrency: 8 }
        };
    } else if (config.protocol === 'shadowsocks') {
        const outboundSettings = {
            servers: [{
                address: config.address,
                port: config.port,
                method: config.method,
                password: config.password
            }]
        };

        const pluginConfig = config.plugin ? parseMaybeJson(config.pluginOpts, null) : null;
        if (config.plugin === 'v2ray-plugin' && pluginConfig) {
            outboundSettings.plugin = 'v2ray-plugin';
            outboundSettings.pluginOpts = pluginConfig;
        }

        proxyOutbound = {
            tag: 'proxy',
            protocol: 'shadowsocks',
            settings: outboundSettings,
            streamSettings: {
                sockopt: fragmentEnabled ? { dialerProxy: 'fragment' } : undefined
            },
            mux: { enabled: false, concurrency: 8 }
        };
    } else if (config.protocol === 'trojan') {
        proxyOutbound = {
            tag: 'proxy',
            protocol: 'trojan',
            settings: {
                servers: [{
                    address: config.address,
                    port: config.port,
                    password: config.password
                }]
            },
            streamSettings: buildCommonStreamSettings(config, fragmentEnabled),
            mux: { enabled: false, concurrency: 8 }
        };
    } else {
        throw new Error(`Unsupported protocol: ${config.protocol}`);
    }

    return {
        log: { loglevel: 'error' },
        dns: { servers: ['8.8.8.8', '1.1.1.1'] },
        inbounds: [{
            tag: 'http-proxy',
            port: proxyPort,
            listen: '127.0.0.1',
            protocol: 'http',
            settings: { auth: 'noauth', allowTransparent: false }
        }],
        outbounds: [
            proxyOutbound,
            {
                tag: 'direct',
                protocol: 'freedom',
                settings: { domainStrategy: 'AsIs', userLevel: 0 }
            },
            {
                tag: 'fragment',
                protocol: 'freedom',
                settings: fragmentEnabled ? {
                    fragment: {
                        packets: FRAGMENT_PACKETS,
                        length: FRAGMENT_LENGTH,
                        interval: FRAGMENT_INTERVAL
                    }
                } : {}
            }
        ],
        routing: {
            domainStrategy: 'AsIs',
            rules: [{
                type: 'field',
                outboundTag: 'proxy',
                domain: ['']
            }]
        }
    };
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
    // Check if input is a config URL (vless, vmess, ss, trojan)
    if (input.startsWith('vless://') || input.startsWith('vmess://') || input.startsWith('ss://') || input.startsWith('trojan://')) {
        const config = parseConfigUrl(input);
        return {
            type: config.protocol,
            config: config
        };
    }

    // Check if input is a file path
    const filePath = resolve(input);
    if (existsSync(filePath)) {
        try {
            const fileContent = readFileSync(filePath, 'utf8');
            const xrayConfig = JSON.parse(fileContent);

            // Extract connection info from xray config for display
            const outbound = xrayConfig.outbounds?.find(o => o.protocol === 'vless' || o.protocol === 'vmess' || o.protocol === 'shadowsocks' || o.protocol === 'trojan');
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

    throw new Error('Input must be either a protocol URL (vless://, vmess://, ss://, trojan://) or a valid xray config file path');
}

// Function to extract connection info from xray outbound for display
function extractConnectionInfo(outbound) {
    const protocol = outbound.protocol || 'unknown';
    const streamSettings = outbound.streamSettings || {};
    
    if (protocol === 'vless') {
        const vnext = outbound.settings?.vnext?.[0];
        return {
            address: vnext?.address || 'unknown',
            port: vnext?.port || 'unknown',
            protocol: protocol,
            security: streamSettings.security || 'none',
            network: streamSettings.network || 'tcp',
            remark: outbound.tag || 'config-file'
        };
    } else if (protocol === 'vmess') {
        const vnext = outbound.settings?.vnext?.[0];
        return {
            address: vnext?.address || 'unknown',
            port: vnext?.port || 'unknown',
            protocol: protocol,
            security: streamSettings.security || 'none',
            network: streamSettings.network || 'tcp',
            remark: outbound.tag || 'config-file'
        };
    } else if (protocol === 'shadowsocks') {
        const server = outbound.settings?.servers?.[0];
        return {
            address: server?.address || 'unknown',
            port: server?.port || 'unknown',
            protocol: protocol,
            security: 'none',
            network: 'tcp',
            remark: outbound.tag || 'config-file'
        };
    } else if (protocol === 'trojan') {
        const server = outbound.settings?.servers?.[0];
        return {
            address: server?.address || 'unknown',
            port: server?.port || 'unknown',
            protocol: protocol,
            security: streamSettings.security || 'tls',
            network: streamSettings.network || 'tcp',
            remark: outbound.tag || 'config-file'
        };
    }
    
    return {
        address: 'unknown',
        port: 'unknown',
        protocol: protocol,
        security: 'unknown',
        network: 'unknown',
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
        // Remove quotes if present in the path
        const cleanPath = xrayPath.replace(/^["']|["']$/g, '');
        const cmd = cleanPath === 'xray' ? 'xray' : `"${cleanPath}"`;

        // If configData is a file path (string without JSON structure)
        if (typeof configData === 'string' && !configData.trim().startsWith('{')) {
            // Use file path method for existing files
            const { stdout, stderr } = await execAsync(`${cmd} -test -config "${configData}"`);
            return { valid: true, message: 'Config is valid' };
        }

        // Use stdin for config validation
        const xrayProcess = spawn(cleanPath === 'xray' ? 'xray' : cleanPath, ['-test', '-config', 'stdin:'], {
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
    const argv = yargs(hideBin(process.argv))
        .scriptName('xping')
        .usage('\nMulti-protocol connection ping tool using Xray with fragment support\nSupports VLESS, VMESS, Shadowsocks (SS), and Trojan protocols\nProject: https://github.com/NabiKAZ/xping\n\nUsage: $0 <input> [options]')
        .updateStrings({
            'Positionals:': 'Arguments:'
        })
        .fail((msg, err, yargs) => {
            if (err) {
                console.error(chalk.red(`❌ Error: ${err.message}`));
            } else {
                console.error(yargs.help());
                console.error('');
                console.error(chalk.red(`❌ ${msg}`));
            }
            process.exit(1);
        })
        .command('$0 <input>', 'Protocol URL (vless://, vmess://, ss://, trojan://) or xray config file path to test', (yargs) => {
            yargs.positional('input', {
                describe: 'Protocol URL or xray config file path to test',
                type: 'string'
            });
        })
        .option('f', {
            alias: 'fragment',
            describe: 'Enable fragment mode',
            type: 'boolean',
            default: false
        })
        .option('d', {
            alias: 'delay',
            describe: 'Delay between pings in milliseconds',
            type: 'number',
            default: 1000
        })
        .option('t', {
            alias: 'timeout',
            describe: 'Connection timeout in milliseconds',
            type: 'number',
            default: 10000
        })
        .option('c', {
            alias: 'count',
            describe: 'Number of pings to send (default: infinite)',
            type: 'number'
        })
        .version('1.0.0')
        .alias('v', 'version')
        .help('h')
        .alias('h', 'help')
        .epilogue(`Examples:
  $ xping "vless://uuid@server:port?security=tls&type=ws&path=/..."
  $ xping "vmess://config-base64"
  $ xping "ss://method:password@server:port"
  $ xping "trojan://password@server:port?security=tls"
  $ xping config.json --fragment --count 10
  $ xping "vless://..." --delay 500 --timeout 10000 --count 5
  $ xping config.json -c 3 -d 2000 -t 5000

Environment Variables:
  XPING_XRAY_PATH          Path to xray binary (default: xray)
  XPING_TARGET_URL         Target URL for testing (default: https://www.google.com/generate_204)
  XPING_FRAGMENT_PACKETS   Fragment packets type (default: tlshello)
  XPING_FRAGMENT_LENGTH    Fragment length range (default: 5-9)
  XPING_FRAGMENT_INTERVAL  Fragment interval range (default: 1-2)

Supported Protocols:
  - VLESS: vless://uuid@server:port?...
  - VMESS: vmess://config-base64
  - Shadowsocks: ss://method:password@server:port
  - Trojan: trojan://password@server:port?...

Note: 
  - When using a config file, it will be processed in memory with a free port (original file unchanged)
  - Fragment mode is only applied to protocol URLs, not config files`)
        .wrap(null)
        .parseSync();

    const input = argv.input;
    const fragmentEnabled = argv.fragment;
    const delay = argv.delay;
    const timeout = argv.timeout;
    const pingCount = argv.count || null; // null means infinite

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

        if (inputData.type !== 'config') {
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
        console.log(chalk.cyanBright(`📍 ${connectionInfo.address}:${connectionInfo.port}`) + chalk.gray(' | ') + chalk.white(connectionInfo.remark) + chalk.gray(' | Protocol: ') + chalk.yellow(connectionInfo.protocol.toUpperCase()));

        if (inputData.type !== 'config') {
            const protocolConfig = inputData.config;
            if (connectionInfo.protocol === 'vless' || connectionInfo.protocol === 'vmess' || connectionInfo.protocol === 'trojan') {
                console.log(chalk.cyanBright(`🔒 ${connectionInfo.security}`) + chalk.gray(' | Type: ') + chalk.yellow(connectionInfo.network) + chalk.gray(' | Host: ') + chalk.yellow(protocolConfig.host || '-') + chalk.gray(' | SNI: ') + chalk.yellow(protocolConfig.sni || '-') + chalk.gray(' | Path: ') + chalk.yellow(protocolConfig.path || '-'));
            } else if (connectionInfo.protocol === 'shadowsocks') {
                console.log(chalk.cyanBright(`🔒 ${protocolConfig.method}`) + chalk.gray(' | Type: ') + chalk.yellow(connectionInfo.network));
            }
        } else {
            console.log(chalk.cyanBright(`🔒 ${connectionInfo.security}`) + chalk.gray(' | Type: ') + chalk.yellow(connectionInfo.network));
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

        // Clean xray path (remove quotes if present)
        const cleanXrayPath = xrayPath.replace(/^["']|["']$/g, '');

        // Start xray process with config via stdin
        const xrayArgs = ['-config', 'stdin:'];
        xrayProcess = spawn(cleanXrayPath === true ? 'xray' : cleanXrayPath, xrayArgs, {
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
