import { useEffect, useState } from 'react';
import {
  motion,
  useMotionValue,
  useReducedMotion,
  useScroll,
  useSpring,
  useTransform,
  type MotionValue,
} from 'motion/react';

/* The room ChainGuard sits in: shields and padlocks floating in real CSS 3D at
   different depths. Shields turn slowly and show their back face; padlocks
   bob. Two layers move differently with the pointer and the scroll — a far
   wash of light and the objects, each by its own depth.

   `calm` is set while the scanner is on screen, so the work area gets a quieter
   room: fewer objects, lower opacity. Transform and opacity only. */

type Obj = {
  kind: 'shield' | 'lock';
  x: string;
  y: string;
  size: number;
  depth: number; // 0 far … 1 near
  spin: number; // seconds per turn
  delay: number;
  mobile: boolean;
  calm: boolean;
};

const OBJECTS: Obj[] = [
  { kind: 'shield', x: '78%', y: '12%', size: 120, depth: 1, spin: 18, delay: 0, mobile: true, calm: true },
  { kind: 'lock', x: '1.5%', y: '46%', size: 64, depth: 0.7, spin: 22, delay: -6, mobile: true, calm: false },
  { kind: 'shield', x: '18%', y: '70%', size: 64, depth: 0.5, spin: 24, delay: -9, mobile: false, calm: false },
  { kind: 'lock', x: '91%', y: '66%', size: 80, depth: 0.85, spin: 20, delay: -3, mobile: true, calm: true },
  { kind: 'shield', x: '52%', y: '86%', size: 48, depth: 0.35, spin: 28, delay: -12, mobile: false, calm: false },
  { kind: 'lock', x: '46%', y: '90%', size: 40, depth: 0.3, spin: 30, delay: -15, mobile: false, calm: false },
];

function useIsMobile() {
  const [mobile, setMobile] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia('(max-width: 767px)');
    const update = () => setMobile(mq.matches);
    update();
    mq.addEventListener('change', update);
    return () => mq.removeEventListener('change', update);
  }, []);
  return mobile;
}

function Floating({ obj, reduce, px, py, scroll }: {
  obj: Obj;
  reduce: boolean;
  px: MotionValue<number>;
  py: MotionValue<number>;
  scroll: MotionValue<number>;
}) {
  const x = useTransform(px, (v) => (reduce ? 0 : v * 50 * obj.depth));
  const y = useTransform([py, scroll] as MotionValue<number>[], ([p, s]: number[]) =>
    reduce ? 0 : p * 32 * obj.depth - s * 320 * obj.depth,
  );
  return (
    <motion.div
      className="amb-obj"
      style={{ left: obj.x, top: obj.y, width: obj.size, height: obj.size * 1.06, x, y }}
    >
      <motion.div
        className={`amb-3d amb-${obj.kind}`}
        initial={{ rotateX: 12, rotateY: obj.kind === 'shield' ? -25 : 20 }}
        animate={
          reduce
            ? undefined
            : obj.kind === 'shield'
              ? { rotateY: [-25, 335], y: [0, -12, 0] }
              : { rotateY: [20, -20, 20], y: [0, -10, 0] }
        }
        transition={
          obj.kind === 'shield'
            ? { rotateY: { duration: obj.spin, repeat: Infinity, ease: 'linear', delay: obj.delay }, y: { duration: 6, repeat: Infinity, ease: 'easeInOut' } }
            : { duration: obj.spin / 3, repeat: Infinity, ease: 'easeInOut', delay: obj.delay / 3 }
        }
      >
        {obj.kind === 'shield' ? (
          <>
            <div className="amb-face amb-front"><div className="amb-mark" /></div>
            <div className="amb-face amb-back" />
          </>
        ) : (
          <>
            <div className="amb-shackle" />
            <div className="amb-body-back" />
            <div className="amb-body" />
          </>
        )}
      </motion.div>
    </motion.div>
  );
}

export default function AmbientBackground({ calm }: { calm: boolean }) {
  const reduce = useReducedMotion() ?? false;
  const mobile = useIsMobile();

  const rx = useMotionValue(0);
  const ry = useMotionValue(0);
  const px = useSpring(rx, { stiffness: 40, damping: 18 });
  const py = useSpring(ry, { stiffness: 40, damping: 18 });
  useEffect(() => {
    if (reduce || !window.matchMedia('(pointer: fine)').matches) return;
    const onMove = (e: PointerEvent) => {
      rx.set((e.clientX / window.innerWidth - 0.5) * 2);
      ry.set((e.clientY / window.innerHeight - 0.5) * 2);
    };
    window.addEventListener('pointermove', onMove, { passive: true });
    return () => window.removeEventListener('pointermove', onMove);
  }, [reduce, rx, ry]);

  const { scrollYProgress } = useScroll();
  const scroll = useSpring(scrollYProgress, { stiffness: 60, damping: 20 });
  const farY = useTransform(scroll, (s) => (reduce ? 0 : s * -40));
  const farX = useTransform(px, (v) => (reduce ? 0 : v * -12));

  const objects = OBJECTS.filter((o) => (calm ? o.calm : true) && (mobile ? o.mobile : true));

  return (
    <div aria-hidden="true" className={`amb-root ${calm ? 'amb-calm' : 'amb-full'}`}>
      <motion.div className="amb-layer amb-far" style={{ y: farY, x: farX }} />
      <div className="amb-vignette" />
      <div className="amb-layer amb-near" style={{ perspective: 800 }}>
        {objects.map((o) => (
          <Floating key={`${o.x}${o.y}`} obj={o} reduce={reduce} px={px} py={py} scroll={scroll} />
        ))}
      </div>
    </div>
  );
}
