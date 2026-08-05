export async function hashPassword(password: string, salt?: string): Promise<{ hash: string, salt: string }> {
    const enc = new TextEncoder();
    const saltStr = salt || window.crypto.randomUUID();
    const saltBuffer = enc.encode(saltStr);
    const passwordBuffer = enc.encode(password);

    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"]
    );

    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: saltBuffer,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        256
    );

    const hashArray = Array.from(new Uint8Array(derivedBits));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return { hash: hashHex, salt: saltStr };
}

/**
 * 常数时间字符串比较（防 timing attack）。
 * Web Crypto 没有 timingSafeEqual，这里手动实现：遍历全部字节累积差异，
 * 执行时间与内容无关。长度不同直接返回 false（hash 长度固定为 64 hex，
 * 长度本身不泄露有用信息）。
 */
export function timingSafeEqualHex(a: string, b: string): boolean {
    const aBytes = new TextEncoder().encode(a);
    const bBytes = new TextEncoder().encode(b);
    if (aBytes.length !== bBytes.length) return false;

    let diff = 0;
    for (let i = 0; i < aBytes.length; i++) {
        diff |= aBytes[i] ^ bBytes[i];
    }
    return diff === 0;
}
