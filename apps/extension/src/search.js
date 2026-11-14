// Transport/browser effects only. Rust owns continuation, aggregation and bounds.
export async function collectLogins(connection, search, { assertCurrent, onProgress, clock, signal }) {
  const started = clock();
  try {
    let complete;
    do {
      signal.throwIfAborted();
      await assertCurrent();
      const reply = await connection.request(JSON.parse(search.request(clock() - started)));
      signal.throwIfAborted();
      await assertCurrent();
      if (reply.status !== 'matches') throw new Error('Unexpected login query reply.');
      complete = search.accept_page(JSON.stringify(reply.page), clock() - started);
      onProgress(search.matches_found());
    } while (!complete);
    return JSON.parse(search.result(clock() - started));
  } catch (error) {
    connection.close();
    throw error;
  } finally { search.free(); }
}
