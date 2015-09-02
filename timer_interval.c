/* vim: set ts=8 sw=4 sts=4 noet: */
/*======================================================================
Copyright (C) 2008,2009,2014 OSSO B.V. <walter+rtpsniff@osso.nl>
This file is part of RTPSniff.

RTPSniff is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

RTPSniff is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License along
with RTPSniff.  If not, see <http://www.gnu.org/licenses/>.
======================================================================*/

#include "rtpsniff.h"
#include <assert.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* Settings */
#ifndef INTERVAL_SECONDS
#   define INTERVAL_SECONDS 10 /* wake the storage engine every N seconds */
#endif /* INTERVAL_SECONDS */

#define TIMER__METHOD_NSLEEP 1
#define TIMER__METHOD_SEMAPHORE 2
#if !defined(USE_NSLEEP_TIMER) && (_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600)
#   define TIMER__METHOD TIMER__METHOD_SEMAPHORE
#   include <errno.h>
#   include <semaphore.h>
#else
#   define TIMER__METHOD TIMER__METHOD_NSLEEP
#endif


static pthread_t timer__thread;
static struct memory_t *timer__memory;
#if TIMER__METHOD == TIMER__METHOD_NSLEEP
static volatile int timer__done;	/* whether we're done */
#elif TIMER__METHOD == TIMER__METHOD_SEMAPHORE
static sem_t timer__semaphore;		/* semaphore to synchronize the threads */
#endif /* TIMER__METHOD == TIMER__METHOD_SEMAPHORE */


static void *timer__run(void *thread_arg);


void timer_help() {
    printf(
	"/*********************"
	" module: timer (interval) *******************************/\n"
	"#%s USE_NSLEEP_TIMER\n"
	"#define INTERVAL_SECONDS %" SCNu32 "\n"
	"\n"
	"Sleeps until the specified interval of %.2f minutes have passed and wakes up\n"
	"to tell the storage engine to write averages.\n"
	"\n"
	"The USE_NSLEEP_TIMER define forces the module to use a polling sleep loop even\n"
	"when the (probably) less cpu intensive and more accurate sem_timedwait()\n"
	"function is available. The currently compiled in timer method is: %s\n"
	"\n",
#ifdef USE_NSLEEP_TIMER
	"define",
#else /* !USE_NSLEEP_TIMER */
	"undef",
#endif
	(uint32_t)INTERVAL_SECONDS, (float)INTERVAL_SECONDS / 60,
#if TIMER__METHOD == TIMER__METHOD_NSLEEP
	"n_sleep"
#elif TIMER__METHOD == TIMER__METHOD_SEMAPHORE
	"semaphore"
#endif /* TIMER__METHOD == TIMER__METHOD_SEMAPHORE */
    );
}

int timer_loop_bg(struct memory_t *memory) {
    pthread_attr_t attr;
    
    /* Set internal config */
    timer__memory = memory;

#if TIMER__METHOD == TIMER__METHOD_NSLEEP
    /* Initialize polling variable */
    timer__done = 0;
#elif TIMER__METHOD == TIMER__METHOD_SEMAPHORE
    /* Initialize semaphore */
    if (sem_init(&timer__semaphore, 0, 0) != 0) {
	perror("sem_init");
	return -1;
    }
#endif /* TIMER__METHOD == TIMER__METHOD_SEMAPHORE */

    /* We want default pthread attributes */
    if (pthread_attr_init(&attr) != 0) {
	perror("pthread_attr_init");
	return -1;
    }
    
    /* Run thread */
    if (pthread_create(&timer__thread, &attr, &timer__run, NULL) != 0) {
	perror("pthread_create");
	return -1;
    }
#ifndef NDEBUG
    fprintf(stderr, "timer_loop_bg: Thread %p started.\n", (void*)timer__thread);
#endif
    return 0;
}

void timer_loop_stop() {
    void *ret;

    /* Tell our thread that it is time */
#if TIMER__METHOD == TIMER__METHOD_NSLEEP
    timer__done = 1;
#elif TIMER__METHOD == TIMER__METHOD_SEMAPHORE
    sem_post(&timer__semaphore);
#endif /* TIMER__METHOD == TIMER__METHOD_SEMAPHORE */

    /* Get its exit status */
    if (pthread_join(timer__thread, &ret) != 0)
	perror("pthread_join");
#ifndef NDEBUG
    fprintf(stderr, "timer_loop_stop: Thread %p joined.\n", (void*)timer__thread);
#endif

#if TIMER__METHOD == TIMER__METHOD_SEMAPHORE
    /* Destroy semaphore */
    if (sem_destroy(&timer__semaphore) != 0)
	perror("sem_destroy");
#endif /* TIMER__METHOD == TIMER__METHOD_SEMAPHORE */
}

/* The timers job is to run storage function after after every INTERVAL_SECONDS time. */
static void *timer__run(void *thread_arg) {
    int first_run_skipped = 0; /* do not store the first run because the interval is wrong */

#ifndef NDEBUG
    fprintf(stderr, "timer__run: Thread started.\n");
#endif

    while (1) {
	struct timeval current_time; /* current time is in UTC */
	int sample_begin_time;
#if TIMER__METHOD == TIMER__METHOD_NSLEEP
	int sleep_useconds;
#elif TIMER__METHOD == TIMER__METHOD_SEMAPHORE
	struct timespec new_time;
	int ret;
#endif /* TIMER__METHOD == TIMER__METHOD_SEMAPHORE */	
	int previously_active;

	/* Get current time */
	if (gettimeofday(&current_time, NULL) != 0) {
	    perror("gettimeofday");
	    return (void*)-1;
	}
    
	/* Yes, we started sampling when SIGUSR1 fired, so this is correct */
	sample_begin_time = current_time.tv_sec - (current_time.tv_sec % INTERVAL_SECONDS);

	/* Calculate how long to sleep */
#if TIMER__METHOD == TIMER__METHOD_NSLEEP
	sleep_useconds = (1000000 *
			  (INTERVAL_SECONDS - (current_time.tv_sec % INTERVAL_SECONDS)) -
			  current_time.tv_usec);
#   ifndef NDEBUG
	fprintf(stderr, "timer__run: Current time is %i (%02i:%02i:%02i.%06i), "
			"sleep planned for %i useconds.\n",
		(int)current_time.tv_sec,
		(int)(current_time.tv_sec / 3600) % 24,
		(int)(current_time.tv_sec / 60) % 60,
		(int)current_time.tv_sec % 60,
		(int)current_time.tv_usec, sleep_useconds);
#   endif /* NDEBUG */
#elif TIMER__METHOD == TIMER__METHOD_SEMAPHORE
	new_time.tv_sec = sample_begin_time + INTERVAL_SECONDS;
	new_time.tv_nsec = 0;
#   ifndef NDEBUG
	fprintf(stderr, "timer__run: Current time is %i (%02i:%02i:%02i.%06i), "
			"sleep planned until %02i:%02i:%02i.\n",
		(int)current_time.tv_sec,
		(int)(current_time.tv_sec / 3600) % 24,
		(int)(current_time.tv_sec / 60) % 60,
		(int)current_time.tv_sec % 60,
		(int)current_time.tv_usec,
		(int)(new_time.tv_sec / 3600) % 24,
		(int)(new_time.tv_sec / 60) % 60,
		(int)new_time.tv_sec % 60);
#   endif /* NDEBUG */
#endif /* TIMER__METHOD == TIMER__METHOD_SEMAPHORE */

#if TIMER__METHOD == TIMER__METHOD_NSLEEP
	/* The sleep in this thread won't wake up (EINTR) from a SIGALRM in the other
	 * thread. Pause/alarm won't work either. We use this crappy polling loop as
	 * an alternative. Observe that the semaphore below method is way more
	 * accurate and probably uses less cpu. */
	while (!timer__done && sleep_useconds > 999999) {
	    sleep(1);
	    sleep_useconds -= 1000000;
	}
	if (timer__done)
	    break;
	usleep(sleep_useconds);
#elif TIMER__METHOD == TIMER__METHOD_SEMAPHORE
	/* The sem_timedwait function will sleep happily until the absolutely specified
	 * time has been reached. */
	while ((ret = sem_timedwait(&timer__semaphore, &new_time)) == -1 && errno == EINTR)
	    continue; /* restart if interrupted by handler */
	if (ret == 0)
	    break; /* if the semaphore was hit, we're done */
	if (errno != ETIMEDOUT)
	    perror("sem_timedwait");
#endif /* TIMER__METHOD == TIMER__METHOD_SEMAPHORE */

#ifndef NDEBUG
	if (gettimeofday(&current_time, NULL) != 0) {
	    perror("gettimeofday");
	    return (void*)-1;
	}
	fprintf(stderr, "timer__run: Awake! Time is now %i (%02i:%02i:%02i.%06i).\n",
		(int)current_time.tv_sec,
		(int)(current_time.tv_sec / 3600) % 24,
		(int)(current_time.tv_sec / 60) % 60,
		(int)current_time.tv_sec % 60,
		(int)current_time.tv_usec);
#endif

	/* Poke other thread to switch memory */
	previously_active = timer__memory->active;
	raise(SIGUSR1);
	sleep(1); /* wait a second to let other thread finish switching memory */

	assert(previously_active != timer__memory->active);

	if (first_run_skipped) {
	    /* Delegate the actual writing to storage. */
	    out_write(sample_begin_time, INTERVAL_SECONDS,
		      timer__memory->data[previously_active]);
	} else {
	    /* On first run, we started too late in the interval. Ignore those counts. */
	    first_run_skipped = 1;
	}

	/* Reset mem for next run */
	sniff_release_data(&timer__memory->data[previously_active]);
    }
    
#ifndef NDEBUG
    fprintf(stderr, "timer__run: Thread done.\n");
#endif
    return 0;
}
