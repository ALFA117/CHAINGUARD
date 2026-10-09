import type { Transition } from 'motion/react';

// One rhythm for the whole app.
export const springSnappy: Transition = { type: 'spring', stiffness: 400, damping: 22 };
export const springPanel: Transition = { type: 'spring', stiffness: 280, damping: 26 };
export const easeEnter: Transition = { duration: 0.4, ease: [0.16, 1, 0.3, 1] };
export const press = { whileHover: { scale: 1.02 }, whileTap: { scale: 0.97 }, transition: springSnappy };
