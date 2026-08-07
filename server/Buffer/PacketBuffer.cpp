#include "PacketBuffer.h"

packet_buffer::packet_buffer()
{
}

packet_buffer::packet_buffer(uint8_t* data, size_t length)
{
	if (data && length) {
		m_data.assign(data, data + length);
	}
}

packet_buffer::packet_buffer(std::vector<uint8_t>&& data) : m_data(std::move(data))
{

}

packet_buffer::packet_buffer(packet_buffer&& other) noexcept
{
	*this = std::move(other);
}

packet_buffer& packet_buffer::operator=(packet_buffer&& other) noexcept
{
	if (this != &other) {
		m_data = std::move(other.m_data);
		m_direction = other.m_direction;
        m_sequence =other.m_sequence;
		m_timestamp = other.m_timestamp;

        other.m_sequence = 0;
        other.m_timestamp =0;
	}
	return *this;
}

uint8_t* packet_buffer::data() {
	return m_data.data();
}
const uint8_t* packet_buffer::get_data() const
{
	return m_data.data();
}

bool packet_buffer::is_empty() const
{
	return m_data.empty();
}

size_t packet_buffer::data_size() const
{
	return m_data.size();
}

void packet_buffer::clear() {
	m_data.clear();
	m_timestamp = 0;
	m_sequence = 0;
}

void packet_buffer::resize(size_t size)
{
	m_data.resize(size);
}

void packet_buffer::set_direction(PacketDirection direction) {
	this->m_direction = direction;
}

uint64_t packet_buffer::sequence() const
{
	return m_sequence;
}

uint64_t packet_buffer::timestamp() const
{
	return m_timestamp;
}

uint64_t packet_buffer::set_sequence(uint64_t sequence) {
	return m_sequence = sequence;
}

uint64_t packet_buffer::set_timestamp(uint64_t timestamp) {
	return m_timestamp = timestamp;
}
