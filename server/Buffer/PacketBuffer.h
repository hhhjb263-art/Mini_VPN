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
	packet_buffer &operator=(packet_buffer&& other) noexcept;
	packet_buffer(const packet_buffer&) = delete;
	packet_buffer& operator=(const packet_buffer&) = delete;
public:
	uint8_t* data();
	const uint8_t *get_data() const;
	bool is_empty() const;
	size_t data_size() const;
	void clear();
	void resize(size_t size);
	void set_direction(PacketDirection direction);
	
public:
	uint64_t sequence() const;
	uint64_t timestamp() const;
	uint64_t set_sequence(uint64_t sequence);
	uint64_t set_timestamp(uint64_t timestamp);
private:
	std::vector<uint8_t> m_data;
	PacketDirection m_direction{
		PacketDirection :: TuntoNetwork
	};
	uint64_t m_sequence{ 0 };
	uint64_t m_timestamp{ 0 };
};

