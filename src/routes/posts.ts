import { Router } from 'express';
import { PostController } from '../controllers/postController';
import { authenticate } from '../middleware/auth';
import { validateBody, createPostSchema, updatePostSchema } from '../middleware/validation';

const router = Router();

router.post('/', authenticate, validateBody(createPostSchema), PostController.createPost);
router.get('/', PostController.getAllPosts);
router.get('/:id', PostController.getPostById);
router.put('/:id', authenticate, validateBody(updatePostSchema), PostController.updatePost);
router.delete('/:id', authenticate, PostController.deletePost);

export default router;