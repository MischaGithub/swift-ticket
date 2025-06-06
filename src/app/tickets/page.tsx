import { getTickets } from "@/actions/ticket.actions";
import { logEvent } from "@/utils/sentry";
import Link from "next/link";
import { getPriorityClass } from "@/utils/ui";
import { getCurrentUser } from "@/lib/current-user";
import { redirect } from "next/navigation";

const TicketsPage = async () => {
  const user = await getCurrentUser();
  const tickets = await getTickets();

  if (!user) {
    redirect("/login");
  }

  return (
    <div className="min-h-screen bg-blue-50 p-8">
      <h1 className="text-3xl font-bold text-blue-600 mb-8 text-center">
        Support Tickets
      </h1>
      {tickets.length === 0 ? (
        <p className="text-center text-gray-600">No Tickets Yet</p>
      ) : (
        <div className="space-y-4 max-w-3xl mx-auto">
          {tickets.map((ticket) => (
            <div
              className="flex justify-between items-center bg-white rounded-lg shadow border border-gray-200 p-6"
              key={ticket.id}
            >
              {/* Left Side */}
              <div>
                <h2 className="text-xl font-semibold text-blue-600">
                  {ticket.subject}
                </h2>
              </div>
              {/* Right Side */}
              <div className="text-right space-y-2">
                <div className="text-sm text-gray-500">
                  Priority:{" "}
                  <span className={getPriorityClass(ticket.priority)}>
                    {ticket.priority}
                  </span>
                </div>
                <Link
                  href={`/tickets/${ticket.id}`}
                  className={
                    "inline-block mt-2 text-sm px-3 py-1 rounded transition text-center bg-blue-600 text-white hover:bg-blue-700"
                  }
                >
                  View Ticket
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default TicketsPage;
