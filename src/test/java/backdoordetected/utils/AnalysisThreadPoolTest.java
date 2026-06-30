package backdoordetected.utils;

import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.ExecutorService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class AnalysisThreadPoolTest {

  @AfterEach
  void tearDown() {
    AnalysisThreadPool.shutdown();
  }

  @Test
  void getSharedReturnsNonNullPool() {
    ExecutorService pool = AnalysisThreadPool.getShared();
    assertNotNull(pool);
    assertFalse(pool.isShutdown());
  }

  @Test
  void getSharedReturnsSameInstanceOnMultipleCalls() {
    ExecutorService pool1 = AnalysisThreadPool.getShared();
    ExecutorService pool2 = AnalysisThreadPool.getShared();
    assertSame(pool1, pool2);
  }

  @Test
  void shutdownTerminatesPool() {
    ExecutorService pool = AnalysisThreadPool.getShared();
    AnalysisThreadPool.shutdown();
    assertTrue(pool.isShutdown() || pool.isTerminated());
  }

  @Test
  void getSharedReturnsNewPoolAfterShutdown() {
    ExecutorService pool1 = AnalysisThreadPool.getShared();
    AnalysisThreadPool.shutdown();
    ExecutorService pool2 = AnalysisThreadPool.getShared();
    assertNotNull(pool2);
    assertFalse(pool2.isShutdown());
  }

  @Test
  void getOptimalThreadCountWithSmallTaskReturnsOne() {
    int count = AnalysisThreadPool.getOptimalThreadCount(1);
    assertTrue(count >= 1);
  }

  @Test
  void getOptimalThreadCountWithZeroTasks() {
    int count = AnalysisThreadPool.getOptimalThreadCount(0);
    assertTrue(count >= 0);
  }

  @Test
  void setEnabledFalseThenGetSharedReturnsNewPool() {
    ExecutorService pool1 = AnalysisThreadPool.getShared();
    AnalysisThreadPool.setEnabled(false);
    ExecutorService pool2 = AnalysisThreadPool.getShared();
    assertNotNull(pool2);
    assertFalse(pool2.isShutdown());
  }

  @Test
  void setEnabledTrueAllowsNewPool() {
    AnalysisThreadPool.setEnabled(true);
    ExecutorService pool = AnalysisThreadPool.getShared();
    assertNotNull(pool);
  }
}
