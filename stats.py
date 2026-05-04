def calculate_stats(packets):
    """Take a list of packet dictionaries and return statistics."""

    if len(packets) == 0:
        return {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "avg_size": 0,
            "max_size": 0,
            "min_size": 0,
            "top_source": "N/A",
            "top_destination": "N/A"
        }

    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    total_size = 0
    sizes = []
    sources = {}      
    destinations = {} 

    for p in packets:
        if p["protocol"] == "TCP":
            tcp_count += 1
        elif p["protocol"] == "UDP":
            udp_count += 1
        elif p["protocol"] == "ICMP":
            icmp_count += 1

        total_size += p["size"]
        sizes.append(p["size"])

        src = p["source_ip"]
        sources[src] = sources.get(src, 0) + 1

        dst = p["destination_ip"]
        destinations[dst] = destinations.get(dst, 0) + 1

    top_source = max(sources, key=sources.get)
    top_destination = max(destinations, key=destinations.get)

    return {
        "total": len(packets),
        "tcp": tcp_count,
        "udp": udp_count,
        "icmp": icmp_count,
        "avg_size": round(total_size / len(packets), 2),
        "max_size": max(sizes),
        "min_size": min(sizes),
        "top_source": top_source,
        "top_destination": top_destination
    }
