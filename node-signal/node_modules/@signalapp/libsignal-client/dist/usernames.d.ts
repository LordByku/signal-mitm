/// <reference types="node" />
export declare function generateCandidates(nickname: string, minNicknameLength: number, maxNicknameLength: number): string[];
export declare function hash(username: string): Buffer;
export declare function generateProof(username: string): Buffer;
export declare function generateProofWithRandom(username: string, random: Buffer): Buffer;
export declare function verifyProof(proof: Buffer, hash: Buffer): void;
