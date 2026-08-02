#include "packet_buffer.h"

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
		m_derection = other.m_derection;
		m_timetamp = other.m_timetamp;
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
	m_timetamp = 0;
	m_sequene = 0;
}

void packet_buffer::resize(size_t size)
{
	m_data.resize(size);
}

void packet_buffer::set_destion(PacketDirection derection) {
	this->m_derection = derection;
}

uint64_t packet_buffer::sequene() const
{
	return m_sequene;
}

uint64_t packet_buffer::timestamp() const
{
	return m_timetamp;
}

uint64_t packet_buffer::set_sequene(uint64_t sequene) {
	return m_sequene = sequene;
}

uint64_t packet_buffer::set_timestamp(uint64_t timetamp) {
	return m_timetamp = timetamp;
}
