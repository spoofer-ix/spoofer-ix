import multiprocessing as mp


class MultiprocessingPool(object):
    """
    Class support multiprocessing calls.
    """

    number_of_concurrent_jobs = mp.cpu_count()

    def __init__(self, max_concurrent_jobs):
        """
        Constructor
        """
        if max_concurrent_jobs is None:
            self.max_concurrent_jobs = MultiprocessingPool.number_of_concurrent_jobs
        else:
            self.max_concurrent_jobs = max_concurrent_jobs

        self.pool = self._setup_pool()

    # Creates the thread pool
    def _setup_pool(self):
        pool = mp.Pool(processes=self.max_concurrent_jobs, maxtasksperchild=1)
        return pool

    # Will run the function with the arguments
    def get_results_map_multiprocessing(self, function_call, args):

        results = self.pool.map(function_call, args)

        # Close the pool
        self.pool.close()

        # Combine the results of the workers
        self.pool.join()

        return results

    # Will run the function with the arguments
    def get_results_imap_multiprocessing(self, function_call, args):

        results = self.pool.imap(function_call, args, chunksize=1)

        # Close the pool
        self.pool.close()

        # Combine the results of the workers
        self.pool.join()

        return results
