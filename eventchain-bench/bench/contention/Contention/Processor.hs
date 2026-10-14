{- | One thread in front of the Hub: the single-threaded event processor as
a thread, with a queue where a real Hub has a socket.

Producers hand a submission to the queue and wait for the reply; the
processor takes submissions in arrival order and appends each through the
Hub's rule. Nothing is checked or written on a Producer's thread, so a
Producer count above one adds load on the processor and nothing else — which
is the point of putting the hop inside the measurement. What the hop costs
here is one runtime handoff each way, a floor under what a network and a
server's request path would add, never a ceiling.

The processor dying is a harness failure, not an outcome: an exception on
the processor thread is rethrown on the thread that opened it, so the run
stops there instead of leaving Producers waiting on replies that will never
come.
-}
module Contention.Processor
    ( withProcessor
    ) where

import Control.Concurrent (forkFinally, killThread, myThreadId, throwTo)
import Control.Concurrent.Chan (newChan, readChan, writeChan)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, takeMVar)
import Control.Exception (AsyncException (ThreadKilled), bracket, fromException)
import Control.Monad (forever)

import Contention.Hub (Checks, Endpoint (..), Outcome, Submission, append, currentHead, withHub)

-- | An empty AOF at @path@ behind a Hub with these checks, served by one thread until the action returns.
withProcessor :: Checks -> FilePath -> (Endpoint -> IO a) -> IO a
withProcessor checks path act = withHub checks path $ \hub -> do
    inbox <- newChan
    caller <- myThreadId
    let serve = forever $ do
            (s, reply) <- readChan inbox
            append hub s >>= putMVar reply
        -- The kill at the end of the action is the processor's normal end; anything else it died of is the caller's failure.
        onExit = \case
            Left e | Just ThreadKilled <- fromException e -> pure ()
            Left e -> throwTo caller e
            Right () -> pure ()
        submitting s = do
            reply <- newEmptyMVar :: IO (MVar Outcome)
            writeChan inbox (s :: Submission, reply)
            takeMVar reply
    bracket (forkFinally serve onExit) killThread $ \_ ->
        act Endpoint{readHead = currentHead hub, submit = submitting}
