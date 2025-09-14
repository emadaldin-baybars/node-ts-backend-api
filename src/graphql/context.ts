import { Request } from 'express';
import { User } from '../models/User';
import { verifyToken } from '../utils/jwt';

export interface GraphQLContext {
  user?: any;
}

export const createContext = async ({ req }: { req: Request }): Promise<GraphQLContext> => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return {};
  }

  try {
    const token = authHeader.substring(7);
    const decoded = verifyToken(token);
    const user = await User.findById(decoded.userId);
    
    if (user && user.isActive) {
      return { user };
    }
  } catch (error) {
    // Invalid token, continue without user
  }

  return {};
};