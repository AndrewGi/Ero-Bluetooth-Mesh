import time
import threading
import heapq
from functools import total_ordering
from typing import *


@total_ordering
class Task:
	def __init__(self, timeout: float) -> None:
		self.timeout = timeout
		self.is_canceled = False
		self.did_run = False
		self.parent: Optional[Scheduler] = None

	def reschedule(self, new_timeout: float) -> None:
		assert not self.is_canceled, "can't reschedule a canceled task (sanity check)"  # can be removed if need be.
		assert self.parent, "missing parent"
		with self.parent.queue_lock:
			try:
				i = self.parent.task_queue.index(self)
			except ValueError as e:
				# we don't exist in the parent queue.
				self.timeout = new_timeout
				self.parent.add_task(self)
				return
			if new_timeout > self.timeout:
				# new larger timeout so we sift up.
				self.timeout = new_timeout
				heapq._siftup(self.parent.task_queue, i)
			else:
				self.timeout = new_timeout
				heapq._siftdown(self.parent.task_queue, 0, i)

	def cancel(self) -> None:
		"""
		Cancels the given task.
		This doesn't remove the task from the Scheduler, but the Scheduler will know not to run the task
		when it's the task's time to fire.
		:return:
		"""
		if self.is_canceled:
			return
		self.is_canceled = True
		self.canceled()

	def fire(self) -> None:
		"""
		Main function called when its the task's turn to run
		:return:
		"""
		pass

	def canceled(self) -> None:
		"""
		Called if the task gets canceled.
		:return:
		"""
		pass

	def __lt__(self, other: 'Task') -> bool:
		return self.timeout < other.timeout

	def __eq__(self, other: 'Task') -> bool:
		return self is other


class Scheduler:
	def __init__(self) -> None:
		self.queue_lock = threading.Lock()
		self.task_queue: List[Task] = list()
		self.task_condition = threading.Condition()
		self.running = True
		self.threshold = .002  # 2 ms threshold
		self.thread = threading.Thread(target=self._scheduler_thread())
		self.thread.start()

	def add_task(self, task: Task) -> None:
		assert task.parent is None
		assert not task.did_run, "task already ran"
		assert task.timeout != 0, "timeout is zero"
		notify = False
		with self.queue_lock:
			if not self.task_queue:
				# empty queue, notify after we add a first task.
				notify = True
			task.parent = self
			heapq.heappush(self.task_queue, task)
		if notify:
			# if we added the first task, notify the thread worker.
			with self.task_condition:
				self.task_condition.notify_all()

	def pop_task(self) -> Tuple[float, Task]:
		with self.queue_lock:
			return heapq.heappop(self.task_queue)

	def peek_task(self) -> Optional[Tuple[float, Task]]:
		return self.task_queue[0] if self.task_queue else None

	def wait_time(self) -> Optional[float]:
		peeked = self.peek_task()
		if not peeked:
			# If no available tasks, return 1 second.
			# _scheduler_thread() should never wait on this 1 second. It checks if the queue is empty
			# before waiting for any set time.
			return 1
		next_time, _ = peeked
		if next_time == 0.0:
			return
		time_delta = next_time - time.time()
		if time_delta < self.threshold:
			# If the task is going to happen soon (ex: 2ms in the future), fire it anyways to save overhead
			# self.threshold can be adjusted to change the thershold time
			return None
		return time_delta

	def _scheduler_thread(self) -> None:
		while self.running:
			with self.task_condition:
				if not self.task_queue:
					# empty task queue
					self.task_condition.wait()
				# otherwise we have a task.
				wait_time = self.wait_time()
				while wait_time is not None:
					self.task_condition.wait(timeout=wait_time)
					wait_time = self.wait_time()
				# wait time is over.
				while wait_time is None:
					task_time, next_task = self.pop_task()
					if not next_task.is_canceled:
						next_task.fire()
						next_task.did_run = True
					wait_time = self.wait_time()
		# If wait time is None again, we have another task to fire.
