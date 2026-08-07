#pragma once
#include <cstdint>
#include <vector>
#include <cstddef>

enum class PacketDirection : uint8_t {
	TuntoNetwork = 0,
	NetworktoTun = 1
};
class packet_buffer
{
public:
	packet_buffer();
	packet_buffer(uint8_t* data, size_t length);
	packet_buffer(std::vector<uint8_t>&& data);
	~packet_buffer() = default;
	packet_buffer(packet_buffer&& other) noexcept;
	packet_buffer & operator=(packet_buffer&& other) noexcept;
	packet_buffer(const packet_buffer&) = delete;
	packet_buffer& operator=(const packet_buffer&) = delete;
public:
	uint8_t* data();
	const uint8_t *get_data() const;
	bool is_empty() const;
	size_t data_size() const;
	void size();
	void clear();
	void resize(size_t size);
	void set_destion(PacketDirection derection);
public:
	uint64_t sequene() const;
	uint64_t timestamp() const;
	uint64_t set_sequene(uint64_t sequene);
	uint64_t set_timestamp(uint64_t timetamp);
private:
	std::vector<uint8_t> m_data;
	PacketDirection m_derection{
		PacketDirection :: TuntoNetwork
	};
	uint64_t m_sequene{ 0 };
	uint64_t m_timetamp{ 0 };
};

