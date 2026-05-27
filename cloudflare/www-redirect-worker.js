export default {
  async fetch(request) {
    const url = new URL(request.url);
    url.protocol = "https:";
    url.hostname = "agent-secret.sh";

    return Response.redirect(url.toString(), 301);
  },
};
