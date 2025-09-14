import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../services/authService';
import { AuthRequest } from '../types/auth';

export class AuthController {
  static async register(req: Request, res: Response, next: NextFunction) {
    try {
      const { user, token } = await AuthService.register(req.body);
      
      res.status(201).json({
        success: true,
        data: { user, token }
      });
    } catch (error) {
      next(error);
    }
  }

  static async login(req: Request, res: Response, next: NextFunction) {
    try {
      const { user, token } = await AuthService.login(req.body);
      
      res.json({
        success: true,
        data: { user, token }
      });
    } catch (error) {
      next(error);
    }
  }

  static async getProfile(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const user = await AuthService.getProfile((req.user!._id as any).toString());
      
      res.json({
        success: true,
        data: user
      });
    } catch (error) {
      next(error);
    }
  }
}