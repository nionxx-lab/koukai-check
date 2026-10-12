// ローカルサーバーをいつ止めるか。
//
// 方式: Ctrl+C（SIGINT / SIGTERM）で即終了。それに加えて、最後にレポートが表示（取得）されてから
// 一定時間たったら自動で終了する。
// レポートは外部リソースを使わない1ファイルの HTML なので、サーバーが止まってもブラウザに表示中の
// ページは消えない（再読み込みだけができなくなる）。そのため「見ている最中に突然消える」ことはない。

export type ExitReason = 'signal' | 'idle';

export interface SignalSource {
  once(event: 'SIGINT' | 'SIGTERM', listener: () => void): unknown;
  off(event: 'SIGINT' | 'SIGTERM', listener: () => void): unknown;
}

export interface WaitOptions {
  idleMs: number;
  /** 最後にレポートが表示された時刻（ミリ秒） */
  lastActivity(): number;
  signals: SignalSource;
  now?: () => number;
  /** 経過時間を確認する間隔 */
  checkEveryMs?: number;
}

export function waitForExit(options: WaitOptions): Promise<ExitReason> {
  const now = options.now ?? Date.now;
  const checkEveryMs = options.checkEveryMs ?? 15_000;

  return new Promise((resolve) => {
    const finish = (reason: ExitReason) => {
      clearInterval(timer);
      options.signals.off('SIGINT', onSignal);
      options.signals.off('SIGTERM', onSignal);
      resolve(reason);
    };
    const onSignal = () => finish('signal');
    const timer = setInterval(() => {
      if (now() - options.lastActivity() >= options.idleMs) finish('idle');
    }, checkEveryMs);
    options.signals.once('SIGINT', onSignal);
    options.signals.once('SIGTERM', onSignal);
  });
}

export class ActivityTracker {
  private last: number;
  constructor(private readonly now: () => number = Date.now) {
    this.last = now();
  }
  touch(): void {
    this.last = this.now();
  }
  lastActivity(): number {
    return this.last;
  }
}
