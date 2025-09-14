import Joi from 'joi';
import { Request, Response, NextFunction } from 'express';

export const validateBody = (schema: Joi.ObjectSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error } = schema.validate(req.body);
    
    if (error) {
      return res.status(400).json({
        success: false,
        error: error.details[0].message
      });
    }
    
    next();
  };
};

// Validation schemas
export const registerSchema = Joi.object({
  username: Joi.string().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});

export const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

export const createPostSchema = Joi.object({
  title: Joi.string().max(200).required(),
  content: Joi.string().max(10000).required(),
  tags: Joi.array().items(Joi.string()),
  isPublished: Joi.boolean()
});

export const updatePostSchema = Joi.object({
  title: Joi.string().max(200),
  content: Joi.string().max(10000),
  tags: Joi.array().items(Joi.string()),
  isPublished: Joi.boolean()
});