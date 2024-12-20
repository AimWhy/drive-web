/**
 * @jest-environment jsdom
 */

import { getArgon2 } from '../../../src/app/crypto/services/utils';

import { describe, expect, it } from 'vitest';

describe('Test getArgon2 with test vectors from the reference implementation that won Password Hashing Competition', () => {
  it('getArgon2 should pass test 1', async () => {
    const password = 'password';
    const salt = 'somesalt';
    const parallelism = 1;
    const iterations = 2;
    const memorySize = 65536;
    const hashLength = 32;
    const result = await getArgon2(password, salt, parallelism, iterations, memorySize, hashLength, 'hex');
    const testResult = '09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7';
    expect(result).toBe(testResult);
  });

  it('getArgon2 should pass test 2', async () => {
    const password = 'password';
    const salt = 'somesalt';
    const parallelism = 1;
    const iterations = 2;
    const memorySize = 262144;
    const hashLength = 32;
    const result = await getArgon2(password, salt, parallelism, iterations, memorySize, hashLength, 'hex');
    const testResult = '78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c';
    expect(result).toBe(testResult);
  });

  it('getArgon2 should pass test 3', async () => {
    const password = 'password';
    const salt = 'somesalt';
    const parallelism = 1;
    const iterations = 2;
    const memorySize = 256;
    const hashLength = 32;
    const result = await getArgon2(password, salt, parallelism, iterations, memorySize, hashLength, 'hex');
    const testResult = '9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe';
    expect(result).toBe(testResult);
  });

  it('getArgon2 should pass test 4', async () => {
    const password = 'password';
    const salt = 'somesalt';
    const parallelism = 2;
    const iterations = 2;
    const memorySize = 256;
    const hashLength = 32;
    const result = await getArgon2(password, salt, parallelism, iterations, memorySize, hashLength, 'hex');
    const testResult = '6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037';
    expect(result).toBe(testResult);
  });

  it('getArgon2 should pass test 5', async () => {
    const password = 'password';
    const salt = 'somesalt';
    const parallelism = 1;
    const iterations = 1;
    const memorySize = 65536;
    const hashLength = 32;
    const result = await getArgon2(password, salt, parallelism, iterations, memorySize, hashLength, 'hex');
    const testResult = 'f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98';
    expect(result).toBe(testResult);
  });

  it('getArgon2 should pass test 6', async () => {
    const password = 'password';
    const salt = 'somesalt';
    const parallelism = 1;
    const iterations = 4;
    const memorySize = 65536;
    const hashLength = 32;
    const result = await getArgon2(password, salt, parallelism, iterations, memorySize, hashLength, 'hex');
    const testResult = '9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c';
    expect(result).toBe(testResult);
  });

  it('getArgon2 should pass test 7', async () => {
    const password = 'differentpassword';
    const salt = 'somesalt';
    const parallelism = 1;
    const iterations = 2;
    const memorySize = 65536;
    const hashLength = 32;
    const result = await getArgon2(password, salt, parallelism, iterations, memorySize, hashLength, 'hex');
    const testResult = '0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde';
    expect(result).toBe(testResult);
  });

  it('getArgon2 should pass test 8', async () => {
    const password = 'password';
    const salt = 'diffsalt';
    const parallelism = 1;
    const iterations = 2;
    const memorySize = 65536;
    const hashLength = 32;
    const result = await getArgon2(password, salt, parallelism, iterations, memorySize, hashLength, 'hex');
    const testResult = 'bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c';
    expect(result).toBe(testResult);
  });
});