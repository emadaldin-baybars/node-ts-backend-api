import { Request, Response, NextFunction } from 'express';
import { UserService } from '../services/userService';
import { AuthRequest } from '../types/auth';

export class UserController {
  static async getAllUsers(req: Request, res: Response, next: NextFunction) {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      
      const result = await UserService.getAllUsers(page, limit);
      
      res.json({
        success: true,
        data: result,
        pagination: {
          page,
          limit,
          total: result.total,
          pages: Math.ceil(result.total / limit)
        }
      });
    } catch (error) {
      next(error);
    }
  }

  static async getUserById(req: Request, res: Response, next: NextFunction) {
    try {
      const user = await UserService.getUserById(req.params.id);
      
      res.json({
        success: true,
        data: user
      });
    } catch (error) {
      next(error);
    }
  }

  static async updateUser(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const userId = req.params.id;
      
      // Users can only update their own profile unless they're admin
      if ((req.user!._id as any).toString() !== userId && req.user!.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
      }

      const user = await UserService.updateUser(userId, req.body);
      
      res.json({
        success: true,
        data: user
      });
    } catch (error) {
      next(error);
    }
  }

  static async deleteUser(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      await UserService.deleteUser(req.params.id);
      
      res.json({
        success: true,
        message: 'User deleted successfully'
      });
    } catch (error) {
      next(error);
    }
  }
}