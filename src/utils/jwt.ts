import jwt from 'jsonwebtoken';
import { ENV } from '../config/env';
import { JWTPayload } from '../types/auth';

export const generateToken = (payload: JWTPayload): string => {
  return jwt.sign(payload, ENV.JWT_SECRET, {
    expiresIn: '7d'
  });
};

export const verifyToken = (token: string): JWTPayload => {
  return jwt.verify(token, ENV.JWT_SECRET) as JWTPayload;
};