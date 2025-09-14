import { Request, Response, NextFunction } from 'express';
import { PostService } from '../services/postService';
import { AuthRequest } from '../types/auth';

export class PostController {
  static async createPost(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const postData = {
        ...req.body,
        author: req.user!._id
      };
      
      const post = await PostService.createPost(postData);
      
      res.status(201).json({
        success: true,
        data: post
      });
    } catch (error) {
      next(error);
    }
  }

  static async getAllPosts(req: Request, res: Response, next: NextFunction) {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const published = req.query.published === 'true' ? true : req.query.published === 'false' ? false : undefined;
      
      const result = await PostService.getAllPosts(page, limit, published);
      
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

  static async getPostById(req: Request, res: Response, next: NextFunction) {
    try {
      const post = await PostService.getPostById(req.params.id);
      
      res.json({
        success: true,
        data: post
      });
    } catch (error) {
      next(error);
    }
  }

  static async updatePost(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      const post = await PostService.updatePost(
        req.params.id,
        req.body,
        (req.user!._id as any).toString()
      );
      
      res.json({
        success: true,
        data: post
      });
    } catch (error) {
      next(error);
    }
  }

  static async deletePost(req: AuthRequest, res: Response, next: NextFunction) {
    try {
      await PostService.deletePost(req.params.id, (req.user!._id as any).toString());
      
      res.json({
        success: true,
        message: 'Post deleted successfully'
      });
    } catch (error) {
      next(error);
    }
  }
}