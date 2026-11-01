package com.autoforge.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "call_traces")
@Getter
@Setter
@NoArgsConstructor
public class CallTrace {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "finding_id", nullable = false)
    private Finding finding;

    @Column(name = "step_number", nullable = false)
    private Integer stepNumber;

    @Column(name = "file_path", nullable = false, length = 512)
    private String filePath;

    @Column(name = "line_number", nullable = false)
    private Integer lineNumber;

    @Column(name = "symbol_name", nullable = false, length = 255)
    private String symbolName;
}
